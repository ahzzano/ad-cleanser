package parser

import (
	"bytes"
	"errors"
	"testing"
)

func wireName(lengths ...int) []byte {
	var name []byte
	for _, length := range lengths {
		name = append(name, byte(length))
		name = append(name, bytes.Repeat([]byte{'a'}, length)...)
	}
	return append(name, 0)
}

func TestQuestionValidation(t *testing.T) {
	maxName := wireName(63, 63, 63, 61)
	longName := wireName(63, 63, 63, 63)
	compressedLong := append(append([]byte{}, maxName...), 1, 'b', 0xc0, 0x0c)
	cases := []struct {
		name   string
		data   []byte
		offset int
		want   error
	}{
		{"empty", nil, 0, ErrorTruncatedDNS},
		{"negative offset", []byte{0}, -1, ErrorInvalidInput},
		{"offset at end", []byte{0}, 1, ErrorTruncatedDNS},
		{"missing label bytes", []byte{3, 'a'}, 0, ErrorTruncatedDNS},
		{"missing terminator", []byte{1, 'a'}, 0, ErrorTruncatedDNS},
		{"missing pointer byte", []byte{0xc0}, 0, ErrorTruncatedDNS},
		{"pointer into header", []byte{0xc0, 0}, 0, ErrorInvalidInput},
		{"pointer past packet", []byte{0xc0, 0xff}, 0, ErrorInvalidInput},
		{"self cycle", []byte{0xc0, 0x0c}, 0, ErrorInvalidInput},
		{"two-pointer cycle", []byte{0xc0, 0x0e, 0xc0, 0x0c}, 0, ErrorInvalidInput},
		{"prefixed cycle", []byte{1, 'a', 0xc0, 0x0c}, 0, ErrorInvalidInput},
		{"missing type", []byte{0}, 0, ErrorTruncatedDNS},
		{"missing class", []byte{0, 0, 1, 0}, 0, ErrorTruncatedDNS},
		{"reserved 01 tag", append([]byte{0x40}, make([]byte, 69)...), 0, ErrorInvalidInput},
		{"reserved 10 tag", append([]byte{0x80}, make([]byte, 133)...), 0, ErrorInvalidInput},
		{"oversized name", append(longName, 0, 1, 0, 1), 0, ErrorInvalidInput},
		{"oversized compressed name", append(compressedLong, 0, 1, 0, 1), len(maxName), ErrorInvalidInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := DNSNameCollection{bytesToParse: tc.data}
			_, _, err := c.parseFromOffset(tc.offset)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestQuestionNameBoundaries(t *testing.T) {
	for _, lengths := range [][]int{nil, {63}, {63, 63, 63, 61}} {
		name := wireName(lengths...)
		c := DNSNameCollection{bytesToParse: append(name, 0, 1, 0, 1)}
		n, next, err := c.parseFromOffset(0)
		var labels [][]byte
		for _, length := range lengths {
			labels = append(labels, bytes.Repeat([]byte{'a'}, length))
		}
		if err != nil || n.name != string(bytes.Join(labels, []byte{'.'})) || n.qType != 1 || n.qClass != 1 || next != len(c.bytesToParse) {
			t.Fatalf("lengths %v: got %+v next=%d err=%v", lengths, n, next, err)
		}
	}
}

func TestQuestionIterationRestarts(t *testing.T) {
	packet := make([]byte, 12)
	packet[5] = 2
	packet = append(packet, 1, 'a', 0, 0, 1, 0, 1, 1, 'b', 0xc0, 0x0c, 0, 28, 0, 1)
	message, err := ParseDNSMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	collection := message.Names()
	seq := collection.All()
	for n := range seq {
		if n.name != "a" {
			t.Fatalf("first name = %q", n.name)
		}
		break
	}
	for range 2 {
		var got []DNSName
		for n := range seq {
			got = append(got, n)
		}
		if len(got) != 2 || got[0] != (DNSName{"a", 1, 1}) || got[1] != (DNSName{"b.a", 28, 1}) {
			t.Fatalf("questions = %+v", got)
		}
	}
}

func TestQuestionRepeatedPointerTargets(t *testing.T) {
	packet := make([]byte, 12)
	packet[5] = 3
	packet = append(packet, 1, 'a', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0xc0, 0x0c, 0, 28, 0, 1)
	message, err := ParseDNSMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	collection := message.Names()
	for range 2 {
		var got []DNSName
		for n := range collection.All() {
			got = append(got, n)
		}
		if len(got) != 3 || got[0] != (DNSName{"a", 1, 1}) || got[1] != (DNSName{"a", 1, 1}) || got[2] != (DNSName{"a", 28, 1}) {
			t.Fatalf("questions = %+v", got)
		}
	}
}

func TestQuestionPointerCleanup(t *testing.T) {
	t.Run("cycle error", func(t *testing.T) {
		c := DNSNameCollection{bytesToParse: []byte{0xc0, 0x0c, 1, 'a', 0, 0, 1, 0, 1}}
		if _, _, err := c.parseFromOffset(0); !errors.Is(err, ErrorInvalidInput) {
			t.Fatalf("error = %v, want %v", err, ErrorInvalidInput)
		}
		n, next, err := c.parseFromOffset(2)
		if err != nil || n != (DNSName{"a", 1, 1}) || next != 9 {
			t.Fatalf("got %+v next=%d err=%v", n, next, err)
		}
	})
	t.Run("empty suffix", func(t *testing.T) {
		c := DNSNameCollection{bytesToParse: []byte{0, 0xc0, 0x0c, 0, 1, 0, 1}}
		for range 2 {
			n, next, err := c.parseFromOffset(1)
			if err != nil || n != (DNSName{"", 1, 1}) || next != 7 {
				t.Fatalf("got %+v next=%d err=%v", n, next, err)
			}
		}
	})
}
