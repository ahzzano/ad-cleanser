package parser

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"time"
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
			c := nameParser{bytesToParse: tc.data}
			_, _, err := c.parseQuestion(tc.offset)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestQuestionNameBoundaries(t *testing.T) {
	for _, lengths := range [][]int{nil, {63}, {63, 63, 63, 61}} {
		name := wireName(lengths...)
		c := nameParser{bytesToParse: append(name, 0, 1, 0, 1)}
		n, next, err := c.parseQuestion(0)
		var labels [][]byte
		for _, length := range lengths {
			labels = append(labels, bytes.Repeat([]byte{'a'}, length))
		}
		if err != nil || n.Name != string(bytes.Join(labels, []byte{'.'})) || n.Type != 1 || n.Class != 1 || next != len(c.bytesToParse) {
			t.Fatalf("lengths %v: got %+v next=%d err=%v", lengths, n, next, err)
		}
	}
}

func TestQuestionRepeatedPointerTargets(t *testing.T) {
	c := nameParser{bytesToParse: []byte{1, 'a', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0xc0, 0x0c, 0, 28, 0, 1}}
	want := []DNSName{{"a", 1, 1}, {"a", 1, 1}, {"a", 28, 1}}
	offset := 0
	for i, w := range want {
		got, next, err := c.parseQuestion(offset)
		if err != nil || got != w {
			t.Fatalf("question %d = %+v, %v; want %+v", i, got, err, w)
		}
		offset = next
	}
}

func TestQuestionCountRejected(t *testing.T) {
	for _, n := range []byte{0, 2} {
		packet := make([]byte, 12)
		packet[5] = n
		if _, err := ParseDNSMessage(packet); !errors.Is(err, ErrorUnsupportedQuestionCount) {
			t.Fatalf("nQuestions=%d: err = %v", n, err)
		}
	}
}

func TestLongPointerChainIsFast(t *testing.T) {
	// Each pointer points at the previous one, ending at a root label.
	buf := []byte{0}
	for i := 0; i < 8000; i++ {
		target := 12 + len(buf) - 1
		if i > 0 {
			target = 12 + len(buf) - 2
		}
		buf = append(buf, 0xc0|byte(target>>8), byte(target))
	}
	buf = append(buf, 0, 1, 0, 1)
	c := nameParser{bytesToParse: buf}
	start := time.Now()
	c.parseQuestion(len(buf) - 6)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestQuestionsMalformed(t *testing.T) {
	for _, test := range []struct {
		name       string
		nQuestions byte
		body       []byte
		want       error
	}{
		{"reserved label tag", 1, []byte{0x40, 0, 0, 1, 0, 1}, ErrorInvalidInput},
		{"truncated question", 1, []byte{1, 'a', 0, 0, 1}, ErrorTruncatedDNS},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := make([]byte, 12)
			packet[5] = test.nQuestions
			message, err := ParseDNSMessage(append(packet, test.body...))
			if err != nil {
				t.Fatal(err)
			}
			if got, err := message.Questions(); !errors.Is(err, test.want) || got != nil {
				t.Fatalf("Questions() = %v, %v; want nil, %v", got, err, test.want)
			}
		})
	}
}

func TestBlockResponse(t *testing.T) {
	const question = "076578616d706c6503636f6d0000010001"
	for _, test := range []struct {
		name         string
		flagsByte    byte
		wantFlagByte byte
	}{
		{"RD", 0x01, 0x81},
		{"opcode and RD", 0x29, 0xA9},
	} {
		t.Run(test.name, func(t *testing.T) {
			// QD=1, AN=1, NS=1, AR=1, with trailing record bytes after the question.
			query, err := hex.DecodeString("123401000001000100010001" + question + "c00c000100010000003c0004010203ff")
			if err != nil {
				t.Fatal(err)
			}
			query[2] = test.flagsByte
			message, err := ParseDNSMessage(query)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString("123401000001000000000000" + question)
			if err != nil {
				t.Fatal(err)
			}
			want[2], want[3] = test.wantFlagByte, 0x83
			got, err := message.BlockResponse()
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("response = %x, %v; want %x", got, err, want)
			}
		})
	}
}

func TestBlockResponseMalformed(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
		want error
	}{
		{"reserved label tag", []byte{0x40, 0, 0, 1, 0, 1}, ErrorInvalidInput},
		{"truncated question", []byte{1, 'a', 0, 0, 1}, ErrorTruncatedDNS},
		{"forward pointer", []byte{0xc0, 0x0e, 1, 'a', 0, 0, 1, 0, 1}, ErrorInvalidInput},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := make([]byte, 12)
			packet[5] = 1
			message, err := ParseDNSMessage(append(packet, test.body...))
			if err != nil {
				t.Fatal(err)
			}
			if got, err := message.BlockResponse(); !errors.Is(err, test.want) || got != nil {
				t.Fatalf("BlockResponse() = %x, %v; want nil, %v", got, err, test.want)
			}
		})
	}
}

func TestQuestionPointerCleanup(t *testing.T) {
	t.Run("cycle error", func(t *testing.T) {
		c := nameParser{bytesToParse: []byte{0xc0, 0x0c, 1, 'a', 0, 0, 1, 0, 1}}
		if _, _, err := c.parseQuestion(0); !errors.Is(err, ErrorInvalidInput) {
			t.Fatalf("error = %v, want %v", err, ErrorInvalidInput)
		}
		n, next, err := c.parseQuestion(2)
		if err != nil || n != (DNSName{"a", 1, 1}) || next != 9 {
			t.Fatalf("got %+v next=%d err=%v", n, next, err)
		}
	})
	t.Run("empty suffix", func(t *testing.T) {
		c := nameParser{bytesToParse: []byte{0, 0xc0, 0x0c, 0, 1, 0, 1}}
		for range 2 {
			n, next, err := c.parseQuestion(1)
			if err != nil || n != (DNSName{"", 1, 1}) || next != 7 {
				t.Fatalf("got %+v next=%d err=%v", n, next, err)
			}
		}
	})
}
