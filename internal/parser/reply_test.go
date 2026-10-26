package parser

import "testing"

func TestIsReplyTo(t *testing.T) {
	// msg builds a message with the given id, flags byte 2, and questions (name, type).
	msg := func(id byte, flags byte, qs ...[2]any) []byte {
		b := []byte{id, 0, flags, 0, 0, byte(len(qs)), 0, 0, 0, 0, 0, 0}
		for _, q := range qs {
			for _, l := range []string{q[0].(string)} {
				start := 0
				for i := 0; i <= len(l); i++ {
					if i == len(l) || l[i] == '.' {
						b = append(b, byte(i-start))
						b = append(b, l[start:i]...)
						start = i + 1
					}
				}
			}
			b = append(b, 0, 0, byte(q[1].(int)), 0, 1)
		}
		return b
	}
	a := [2]any{"example.com", 1}
	query := msg(1, 0, a)
	tests := []struct {
		name  string
		reply []byte
		want  bool
	}{
		{"match", msg(1, 0x80, a), true},
		{"id mismatch", msg(2, 0x80, a), false},
		{"QR unset", msg(1, 0, a), false},
		{"name case", msg(1, 0x80, [2]any{"EXAMPLE.com", 1}), true},
		{"type differs", msg(1, 0x80, [2]any{"example.com", 28}), false},
		{"question count", msg(1, 0x80, a, a), false},
		{"short", []byte{1}, false},
	}
	for _, tc := range tests {
		if got := mustParse(t, query).IsReplyTo(tc.reply); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}
