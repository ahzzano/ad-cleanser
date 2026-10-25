package parser

import (
	"encoding/binary"
	"errors"
	"strings"
)

type DNSMessage struct {
	id             uint16
	flags          uint16
	nQuestions     uint16
	nAnswerRRs     uint16
	nAuthorityRRs  uint16
	nAdditionalRRs uint16
	message        []byte
}

type nameParser struct {
	bytesToParse []byte
}

type DNSName struct {
	Name  string
	Type  uint16
	Class uint16
}

func (c *nameParser) parseName(offset int) (string, int, error) {
	if offset < 0 {
		return "", 0, ErrorInvalidInput
	}
	if offset >= len(c.bytesToParse) {
		return "", 0, ErrorTruncatedDNS
	}
	nextStringLength := c.bytesToParse[offset]
	partialNames := make([]string, 0, 3)
	nameLength := 1 // Include the terminating root label.

	i := offset + 1
	for nextStringLength > 0 {
		if nextStringLength&0xC0 == 0xC0 {
			if i >= len(c.bytesToParse) {
				return "", 0, ErrorTruncatedDNS
			}
			packetOffset := int(nextStringLength&0x3F)<<8 | int(c.bytesToParse[i])
			target := packetOffset - 12
			if target < 0 || target >= len(c.bytesToParse) || target >= offset { // pointers must point backward
				return "", 0, ErrorInvalidInput
			}

			name, _, err := c.parseName(target)
			if err != nil {
				return "", 0, err
			}
			if name != "" {
				if nameLength+len(name)+1 > 255 {
					return "", 0, ErrorInvalidInput
				}
				partialNames = append(partialNames, name)
			}
			return strings.Join(partialNames, "."), i + 1, nil
		}
		if nextStringLength&0xC0 != 0 {
			return "", 0, ErrorInvalidInput
		}
		nameLength += int(nextStringLength) + 1
		if nameLength > 255 {
			return "", 0, ErrorInvalidInput
		}
		if int(nextStringLength) >= len(c.bytesToParse)-i {
			return "", 0, ErrorTruncatedDNS
		}

		str := string(c.bytesToParse[i : i+int(nextStringLength)])
		partialNames = append(partialNames, str)

		i += int(nextStringLength)
		nextStringLength = c.bytesToParse[i]
		i += 1
	}

	name := strings.Join(partialNames, ".")

	return name, i, nil
}

func (c *nameParser) parseQuestion(offset int) (DNSName, int, error) {
	name, nextOffset, err := c.parseName(offset)
	if err != nil {
		return DNSName{}, 0, err
	}
	if len(c.bytesToParse)-nextOffset < 4 {
		return DNSName{}, 0, ErrorTruncatedDNS
	}
	qType := binary.BigEndian.Uint16(c.bytesToParse[nextOffset : nextOffset+2])
	qClass := binary.BigEndian.Uint16(c.bytesToParse[nextOffset+2 : nextOffset+4])

	return DNSName{Name: name, Type: qType, Class: qClass}, nextOffset + 4, nil
}

var (
	ErrorInvalidInput = errors.New("Input is an invalid input")
	ErrorTruncatedDNS = errors.New("DNS message is truncated")

	ErrorUnsupportedQuestionCount = errors.New("DNS message must have exactly one question")
)

func (m DNSMessage) Questions() ([]DNSName, error) {
	qs, _, err := m.parseQuestions()
	return qs, err
}

// parseQuestions returns the questions and the offset in m.message where the question section ends.
func (m DNSMessage) parseQuestions() ([]DNSName, int, error) {
	p := nameParser{bytesToParse: m.message}
	// A question needs at least 5 bytes, so cap the preallocation by message size, not the header count.
	questions := make([]DNSName, 0, min(int(m.nQuestions), len(m.message)/5))
	offset := 0
	for range m.nQuestions {
		q, next, err := p.parseQuestion(offset)
		if err != nil {
			return nil, 0, err
		}
		questions = append(questions, q)
		offset = next
	}
	return questions, offset, nil
}

func ParseDNSMessage(message []byte) (DNSMessage, error) {
	if len(message) < 12 {
		return DNSMessage{}, ErrorTruncatedDNS
	}

	if n := binary.BigEndian.Uint16(message[4:6]); n != maxQuestions {
		return DNSMessage{}, ErrorUnsupportedQuestionCount
	}

	id := binary.BigEndian.Uint16(message[:2])
	flags := binary.BigEndian.Uint16(message[2:4])
	noOfQuestions := binary.BigEndian.Uint16(message[4:6])
	numberOfAnswerRRs := binary.BigEndian.Uint16(message[6:8])
	numberOfAuthorityRRs := binary.BigEndian.Uint16(message[8:10])
	numberOfAdditionalRRs := binary.BigEndian.Uint16(message[10:12])

	return DNSMessage{
		id:             id,
		flags:          flags,
		nQuestions:     noOfQuestions,
		nAnswerRRs:     numberOfAnswerRRs,
		nAuthorityRRs:  numberOfAuthorityRRs,
		nAdditionalRRs: numberOfAdditionalRRs,
		message:        message[12:],
	}, nil
}

// maxQuestions bounds per-packet parse work; real resolvers send exactly one.
const maxQuestions = 1

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
	if len(query) < 12 {
		return nil
	}
	flags := binary.BigEndian.Uint16(query[2:4])
	if flags&flagQR != 0 {
		return nil
	}
	resp := make([]byte, 12)
	copy(resp, query[:2])
	binary.BigEndian.PutUint16(resp[2:4], flags&flagOpcodeRD|flagQR|flagRA|rcode)
	return resp
}

// BlockResponse builds an NXDOMAIN reply that echoes only the header and question section.
func (m DNSMessage) BlockResponse() ([]byte, error) { return m.Response(rcodeNXDomain) }

// Response builds a reply with the given rcode that echoes only the header and question section.
func (m DNSMessage) Response(rcode uint16) ([]byte, error) {
	_, end, err := m.parseQuestions()
	if err != nil {
		return nil, err
	}
	flags := m.flags&flagOpcodeRD | flagQR | flagRA | rcode
	response := make([]byte, 0, 12+end)
	response = binary.BigEndian.AppendUint16(response, m.id)
	response = binary.BigEndian.AppendUint16(response, flags)
	response = binary.BigEndian.AppendUint16(response, m.nQuestions)
	response = binary.BigEndian.AppendUint16(response, 0)
	response = binary.BigEndian.AppendUint16(response, 0)
	response = binary.BigEndian.AppendUint16(response, 0)
	return append(response, m.message[:end]...), nil
}

// IsReplyTo reports whether reply is a response to query: same ID, QR set, same questions.
func IsReplyTo(query, reply []byte) bool {
	if len(reply) < 12 || len(query) < 12 || reply[0] != query[0] || reply[1] != query[1] || reply[2]&0x80 == 0 {
		return false
	}
	qm, err := ParseDNSMessage(query)
	if err != nil {
		return false
	}
	qs, err := qm.Questions()
	if err != nil {
		return false
	}
	rm, err := ParseDNSMessage(reply)
	if err != nil {
		return false
	}
	rs, err := rm.Questions()
	if err != nil || len(qs) != len(rs) {
		return false
	}
	for i := range rs {
		if !strings.EqualFold(qs[i].Name, rs[i].Name) || qs[i].Type != rs[i].Type || qs[i].Class != rs[i].Class {
			return false
		}
	}
	return true
}

const (
	defaultUDPSize = 512
	flagTC         = 0x0200
	typeOPT        = 41
)

// skipName returns the offset after the (possibly compressed) name at off, or -1 if malformed.
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
	_, off, err := m.parseQuestions()
	if err != nil {
		return defaultUDPSize
	}
	b := m.message
	total := int(m.nAnswerRRs) + int(m.nAuthorityRRs) + int(m.nAdditionalRRs)
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

// TruncateResponse returns resp if it fits in limit bytes; otherwise a valid reply
// with TC set holding only the header and question section.
func TruncateResponse(resp []byte, limit int) []byte {
	if len(resp) <= limit || len(resp) < 12 {
		return resp
	}
	out := make([]byte, 12)
	copy(out, resp[:4])
	out[2] |= flagTC >> 8
	if m, err := ParseDNSMessage(resp); err == nil {
		if _, end, err := m.parseQuestions(); err == nil {
			binary.BigEndian.PutUint16(out[4:], m.nQuestions)
			out = append(out, m.message[:end]...)
		}
	}
	return out
}
