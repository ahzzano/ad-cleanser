package parser

import "testing"

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
