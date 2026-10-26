package parser

import (
	"encoding/binary"
	"errors"
	"strings"
)

const headerLen = 12

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type DNSMessage struct {
	Question Question
	flags    uint16
	packet   []byte // full packet; all offsets are packet-relative
	qEnd     int    // offset where the question section ends
}

var (
	ErrInvalidInput = errors.New("invalid DNS input")
	ErrTruncatedDNS = errors.New("DNS message is truncated")

	ErrUnsupportedQuestionCount = errors.New("DNS message must have exactly one question")
)

// parseName returns the (possibly compressed) name at off and the offset just after it in b.
func parseName(b []byte, off int) (string, int, error) {
	if off < 0 {
		return "", 0, ErrInvalidInput
	}
	if off >= len(b) {
		return "", 0, ErrTruncatedDNS
	}
	labelLen := b[off]
	var labels []string
	nameLength := 1 // Include the terminating root label.

	i := off + 1
	for labelLen > 0 {
		if labelLen&0xC0 == 0xC0 {
			if i >= len(b) {
				return "", 0, ErrTruncatedDNS
			}
			target := int(labelLen&0x3F)<<8 | int(b[i])
			if target < headerLen || target >= len(b) || target >= off { // pointers must point backward
				return "", 0, ErrInvalidInput
			}

			name, _, err := parseName(b, target)
			if err != nil {
				return "", 0, err
			}
			if name != "" {
				if nameLength+len(name)+1 > 255 {
					return "", 0, ErrInvalidInput
				}
				labels = append(labels, name)
			}
			return strings.Join(labels, "."), i + 1, nil
		}
		if labelLen&0xC0 != 0 {
			return "", 0, ErrInvalidInput
		}
		nameLength += int(labelLen) + 1
		if nameLength > 255 {
			return "", 0, ErrInvalidInput
		}
		if int(labelLen) >= len(b)-i {
			return "", 0, ErrTruncatedDNS
		}

		labels = append(labels, string(b[i:i+int(labelLen)]))

		i += int(labelLen)
		labelLen = b[i]
		i++
	}

	return strings.Join(labels, "."), i, nil
}

func parseQuestion(b []byte, off int) (Question, int, error) {
	name, next, err := parseName(b, off)
	if err != nil {
		return Question{}, 0, err
	}
	if len(b)-next < 4 {
		return Question{}, 0, ErrTruncatedDNS
	}
	return Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(b[next:]),
		Class: binary.BigEndian.Uint16(b[next+2:]),
	}, next + 4, nil
}

// ParseDNSMessage parses the header and the single question. The packet is retained, not copied.
func ParseDNSMessage(packet []byte) (DNSMessage, error) {
	if len(packet) < headerLen {
		return DNSMessage{}, ErrTruncatedDNS
	}
	if binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return DNSMessage{}, ErrUnsupportedQuestionCount
	}
	q, end, err := parseQuestion(packet, headerLen)
	if err != nil {
		return DNSMessage{}, err
	}
	return DNSMessage{
		Question: q,
		flags:    binary.BigEndian.Uint16(packet[2:4]),
		packet:   packet,
		qEnd:     end,
	}, nil
}

const (
	flagQR        = 0x8000          // response
	flagRA        = 0x0080          // recursion available
	flagOpcodeRD  = 0x7800 | 0x0100 // preserved from the query: opcode and RD
	rcodeNXDomain = 3
)

const (
	FormErr  = 1
	ServFail = 2
	NotImp   = 4
)

func (m DNSMessage) Opcode() uint8    { return uint8(m.flags >> 11 & 0xF) }
func (m DNSMessage) IsResponse() bool { return m.flags&flagQR != 0 }

// ErrorResponse builds a header-only reply for an unparseable query; nil if query is too short or is itself a response.
func ErrorResponse(query []byte, rcode uint16) []byte {
	if len(query) < headerLen {
		return nil
	}
	flags := binary.BigEndian.Uint16(query[2:4])
	if flags&flagQR != 0 {
		return nil
	}
	resp := make([]byte, headerLen)
	copy(resp, query[:2])
	binary.BigEndian.PutUint16(resp[2:4], flags&flagOpcodeRD|flagQR|flagRA|rcode)
	return resp
}

// blockTTL is how long clients cache a blocked answer, so also how long an unblock takes to reach them.
const blockTTL = 300

// BlockResponse builds an NXDOMAIN reply echoing the question, with one SOA in the
// authority section so clients negatively cache it (RFC 2308) for blockTTL seconds.
func (m DNSMessage) BlockResponse() []byte {
	resp := m.Response(rcodeNXDomain)
	binary.BigEndian.PutUint16(resp[8:], 1) // NSCOUNT
	const ptr = 0xC000 | headerLen          // the question name always starts at offset 12
	resp = binary.BigEndian.AppendUint16(resp, ptr)
	resp = binary.BigEndian.AppendUint16(resp, 6) // SOA
	resp = binary.BigEndian.AppendUint16(resp, m.Question.Class)
	resp = binary.BigEndian.AppendUint32(resp, blockTTL)
	resp = binary.BigEndian.AppendUint16(resp, 24)              // RDLENGTH
	resp = binary.BigEndian.AppendUint16(resp, ptr)             // MNAME
	resp = binary.BigEndian.AppendUint16(resp, ptr)             // RNAME
	for _, v := range []uint32{1, 3600, 600, 86400, blockTTL} { // serial, refresh, retry, expire, minimum
		resp = binary.BigEndian.AppendUint32(resp, v)
	}
	return resp
}

// Response builds a reply with the given rcode that echoes only the header and question section.
func (m DNSMessage) Response(rcode uint16) []byte {
	resp := make([]byte, headerLen, m.qEnd)
	copy(resp, m.packet[:2])
	binary.BigEndian.PutUint16(resp[2:], m.flags&flagOpcodeRD|flagQR|flagRA|rcode)
	binary.BigEndian.PutUint16(resp[4:], 1)
	return append(resp, m.packet[headerLen:m.qEnd]...)
}

// IsReplyTo reports whether reply is a response to query: same ID, QR set, same question.
func IsReplyTo(query, reply []byte) bool {
	if len(reply) < headerLen || len(query) < headerLen || reply[0] != query[0] || reply[1] != query[1] || reply[2]&(flagQR>>8) == 0 {
		return false
	}
	qm, err := ParseDNSMessage(query)
	if err != nil {
		return false
	}
	rm, err := ParseDNSMessage(reply)
	if err != nil {
		return false
	}
	q, r := qm.Question, rm.Question
	return strings.EqualFold(q.Name, r.Name) && q.Type == r.Type && q.Class == r.Class
}

const (
	defaultUDPSize = 512
	flagTC         = 0x0200
	typeOPT        = 41
)

// skipName returns the offset after the (possibly compressed) name at off, or -1 if malformed.
// It walks labels without decoding so UDPSize stays allocation-free on every query.
func skipName(b []byte, off int) int {
	for off < len(b) {
		l := int(b[off])
		switch {
		case l == 0:
			return off + 1
		case l&0xC0 == 0xC0:
			if off+2 > len(b) {
				return -1
			}
			return off + 2
		case l&0xC0 != 0:
			return -1
		}
		if off+1+l > len(b) {
			return -1
		}
		off += 1 + l
	}
	return -1
}

// UDPSize returns the largest UDP reply the query's sender accepts: 512, or its EDNS0 payload size if larger.
func UDPSize(query []byte) int {
	m, err := ParseDNSMessage(query)
	if err != nil {
		return defaultUDPSize
	}
	b, off := m.packet, m.qEnd
	total := int(binary.BigEndian.Uint16(b[6:])) + int(binary.BigEndian.Uint16(b[8:])) + int(binary.BigEndian.Uint16(b[10:]))
	for range total {
		if off = skipName(b, off); off < 0 || off+10 > len(b) {
			return defaultUDPSize
		}
		typ := binary.BigEndian.Uint16(b[off:])
		class := int(binary.BigEndian.Uint16(b[off+2:]))
		rdlen := int(binary.BigEndian.Uint16(b[off+8:]))
		if typ == typeOPT {
			return max(class, defaultUDPSize)
		}
		if off += 10 + rdlen; off > len(b) {
			return defaultUDPSize
		}
	}
	return defaultUDPSize
}

// IsTruncated reports whether resp has the TC bit set.
func IsTruncated(resp []byte) bool {
	return len(resp) >= headerLen && resp[2]&(flagTC>>8) != 0
}

// TruncateResponse returns resp if it fits in limit bytes; otherwise a valid reply
// with TC set holding only the header and question section.
func TruncateResponse(resp []byte, limit int) []byte {
	if len(resp) <= limit || len(resp) < headerLen {
		return resp
	}
	out := make([]byte, headerLen)
	copy(out, resp[:4])
	out[2] |= flagTC >> 8
	if m, err := ParseDNSMessage(resp); err == nil {
		binary.BigEndian.PutUint16(out[4:], 1)
		out = append(out, m.packet[headerLen:m.qEnd]...)
	}
	return out
}
