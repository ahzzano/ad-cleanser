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

// withHeader prefixes data with a zeroed 12-byte header so offsets and pointers are packet-relative.
func withHeader(data []byte) []byte { return append(make([]byte, headerLen), data...) }

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
		{"empty", nil, 0, ErrTruncatedDNS},
		{"negative offset", []byte{0}, -headerLen - 1, ErrInvalidInput},
		{"offset at end", []byte{0}, 1, ErrTruncatedDNS},
		{"missing label bytes", []byte{3, 'a'}, 0, ErrTruncatedDNS},
		{"missing terminator", []byte{1, 'a'}, 0, ErrTruncatedDNS},
		{"missing pointer byte", []byte{0xc0}, 0, ErrTruncatedDNS},
		{"pointer into header", []byte{0xc0, 0}, 0, ErrInvalidInput},
		{"pointer past packet", []byte{0xc0, 0xff}, 0, ErrInvalidInput},
		{"self cycle", []byte{0xc0, 0x0c}, 0, ErrInvalidInput},
		{"two-pointer cycle", []byte{0xc0, 0x0e, 0xc0, 0x0c}, 0, ErrInvalidInput},
		{"prefixed cycle", []byte{1, 'a', 0xc0, 0x0c}, 0, ErrInvalidInput},
		{"missing type", []byte{0}, 0, ErrTruncatedDNS},
		{"missing class", []byte{0, 0, 1, 0}, 0, ErrTruncatedDNS},
		{"reserved 01 tag", append([]byte{0x40}, make([]byte, 69)...), 0, ErrInvalidInput},
		{"reserved 10 tag", append([]byte{0x80}, make([]byte, 133)...), 0, ErrInvalidInput},
		{"oversized name", append(longName, 0, 1, 0, 1), 0, ErrInvalidInput},
		{"oversized compressed name", append(compressedLong, 0, 1, 0, 1), len(maxName), ErrInvalidInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseQuestion(withHeader(tc.data), tc.offset+headerLen)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestQuestionNameBoundaries(t *testing.T) {
	for _, lengths := range [][]int{nil, {63}, {63, 63, 63, 61}} {
		name := wireName(lengths...)
		b := withHeader(append(name, 0, 1, 0, 1))
		n, next, err := parseQuestion(b, headerLen)
		var labels [][]byte
		for _, length := range lengths {
			labels = append(labels, bytes.Repeat([]byte{'a'}, length))
		}
		if err != nil || n.Name != string(bytes.Join(labels, []byte{'.'})) || n.Type != 1 || n.Class != 1 || next != len(b) {
			t.Fatalf("lengths %v: got %+v next=%d err=%v", lengths, n, next, err)
		}
	}
}

func TestQuestionRepeatedPointerTargets(t *testing.T) {
	b := withHeader([]byte{1, 'a', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0xc0, 0x0c, 0, 28, 0, 1})
	want := []Question{{"a", 1, 1}, {"a", 1, 1}, {"a", 28, 1}}
	offset := headerLen
	for i, w := range want {
		got, next, err := parseQuestion(b, offset)
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
		if _, err := ParseDNSMessage(packet); !errors.Is(err, ErrUnsupportedQuestionCount) {
			t.Fatalf("nQuestions=%d: err = %v", n, err)
		}
	}
}

func TestLongPointerChainIsFast(t *testing.T) {
	// Each pointer points at the previous one, ending at a root label.
	buf := withHeader([]byte{0})
	for i := 0; i < 8000; i++ {
		target := len(buf) - 1
		if i > 0 {
			target = len(buf) - 2
		}
		buf = append(buf, 0xc0|byte(target>>8), byte(target))
	}
	buf = append(buf, 0, 1, 0, 1)
	start := time.Now()
	parseQuestion(buf, len(buf)-6)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v", d)
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
			if message.Question != (Question{"example.com", 1, 1}) {
				t.Fatalf("question = %+v", message.Question)
			}
			want, err := hex.DecodeString("123401000001000000000000" + question)
			if err != nil {
				t.Fatal(err)
			}
			want[2], want[3] = test.wantFlagByte, 0x83
			if got := message.BlockResponse(); !bytes.Equal(got, want) {
				t.Fatalf("response = %x; want %x", got, want)
			}
		})
	}
}

func TestParseMalformedQuestion(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
		want error
	}{
		{"reserved label tag", []byte{0x40, 0, 0, 1, 0, 1}, ErrInvalidInput},
		{"truncated question", []byte{1, 'a', 0, 0, 1}, ErrTruncatedDNS},
		{"forward pointer", []byte{0xc0, 0x0e, 1, 'a', 0, 0, 1, 0, 1}, ErrInvalidInput},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := make([]byte, headerLen)
			packet[5] = 1
			if _, err := ParseDNSMessage(append(packet, test.body...)); !errors.Is(err, test.want) {
				t.Fatalf("err = %v, want %v", err, test.want)
			}
		})
	}
}

func TestIsTruncated(t *testing.T) {
	h := make([]byte, headerLen)
	if IsTruncated(h) || IsTruncated(h[:2]) {
		t.Fatal("unexpected TC")
	}
	h[2] = 0x02
	if !IsTruncated(h) || IsTruncated(h[:3]) {
		t.Fatal("TC not detected")
	}
}

func TestQuestionPointerCleanup(t *testing.T) {
	t.Run("cycle error", func(t *testing.T) {
		b := withHeader([]byte{0xc0, 0x0c, 1, 'a', 0, 0, 1, 0, 1})
		if _, _, err := parseQuestion(b, headerLen); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidInput)
		}
		n, next, err := parseQuestion(b, headerLen+2)
		if err != nil || n != (Question{"a", 1, 1}) || next != headerLen+9 {
			t.Fatalf("got %+v next=%d err=%v", n, next, err)
		}
	})
	t.Run("empty suffix", func(t *testing.T) {
		b := withHeader([]byte{0, 0xc0, 0x0c, 0, 1, 0, 1})
		for range 2 {
			n, next, err := parseQuestion(b, headerLen+1)
			if err != nil || n != (Question{"", 1, 1}) || next != headerLen+7 {
				t.Fatalf("got %+v next=%d err=%v", n, next, err)
			}
		}
	})
}

func TestUDPSizeAndTruncate(t *testing.T) {
	q := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
	withOPT := func(size uint16) []byte {
		e := append([]byte{}, q...)
		e[11] = 1
		return append(e, 0, 0, 41, byte(size>>8), byte(size), 0, 0, 0, 0, 0, 0)
	}
	if got := UDPSize(q); got != 512 {
		t.Fatalf("plain=%d", got)
	}
	for size, want := range map[uint16]int{1232: 1232, 100: 512, 512: 512} {
		if got := UDPSize(withOPT(size)); got != want {
			t.Fatalf("opt %d: got %d want %d", size, got, want)
		}
	}
	e := withOPT(4096)
	if got := UDPSize(e[:len(e)-3]); got != 512 {
		t.Fatalf("malformed=%d", got)
	}
	// non-OPT record whose rdlen runs past the buffer
	bad := append([]byte{}, q...)
	bad[7] = 1
	bad = append(bad, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0xFF, 0xFF)
	if got := UDPSize(bad); got != 512 {
		t.Fatalf("rdlen overrun=%d", got)
	}
	// name label running past the buffer
	if got := UDPSize(append(append([]byte{}, withOPT(4096)[:len(q)]...), 50, 'x')); got != 512 {
		t.Fatalf("label overrun=%d", got)
	}

	resp := append([]byte{}, q...)
	resp[2], resp[3], resp[5], resp[7], resp[9], resp[11] = 0x85, 0x83, 1, 1, 2, 3
	resp = append(resp, make([]byte, 600)...)
	if got := TruncateResponse(resp, 1000); len(got) != len(resp) {
		t.Fatal("changed small reply")
	}
	got := TruncateResponse(resp, 512)
	if !bytes.Equal(got[:2], resp[:2]) || got[2] != resp[2]|0x02 || got[3] != resp[3] ||
		!bytes.Equal(got[4:6], resp[4:6]) || !bytes.Equal(got[6:12], make([]byte, 6)) ||
		!bytes.Equal(got[12:], q[12:]) {
		t.Fatalf("bad truncation: %v", got)
	}
}
