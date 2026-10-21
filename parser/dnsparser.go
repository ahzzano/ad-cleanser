package parser

import (
	"encoding/binary"
	"errors"
	"iter"
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

type DNSNameCollection struct {
	nQuestions     int
	currentOffset  int
	bytesToParse   []byte
	stringPointers []int
}

type DNSName struct {
	name   string
	qType  uint16
	qClass uint16
}

func (c *DNSNameCollection) parseName(offset int) (string, int, error) {
	nextStringLength := c.bytesToParse[offset]
	partialNames := make([]string, 0, 3)

	i := offset + 1
	for nextStringLength > 0 {
		if nextStringLength&0xC0 == 0xC0 {
			packetOffset := int(nextStringLength&0x3F)<<8 | int(c.bytesToParse[i])
			target := packetOffset - 12
			name, _, err := c.parseName(target)
			if err != nil {
				return "", 0, err
			}
			if name != "" {
				partialNames = append(partialNames, name)
			}
			return strings.Join(partialNames, "."), i + 1, nil
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

func (c *DNSNameCollection) parseFromOffset(offset int) (DNSName, int, error) {
	name, nextOffset, err := c.parseName(offset)
	if err != nil {
		return DNSName{}, 0, err
	}
	qType := binary.BigEndian.Uint16(c.bytesToParse[nextOffset : nextOffset+2])
	qClass := binary.BigEndian.Uint16(c.bytesToParse[nextOffset+2 : nextOffset+4])

	return DNSName{name: name, qType: qType, qClass: qClass}, nextOffset + 4, nil
}

func (c *DNSNameCollection) All() iter.Seq[DNSName] {
	return func(yield func(DNSName) bool) {
		for i := 0; i < c.nQuestions; i++ {
			name, nextOffset, err := c.parseFromOffset(c.currentOffset)
			if err != nil {
				return
			}
			c.currentOffset = nextOffset
			if !yield(name) {
				return
			}
		}
	}
}

var (
	ErrorInvalidInput = errors.New("Input is an invalid input")
	ErrorTruncatedDNS = errors.New("DNS message is truncated")
)

func (m *DNSMessage) Names() DNSNameCollection {
	return DNSNameCollection{
		nQuestions:     int(m.nQuestions),
		currentOffset:  0,
		bytesToParse:   m.message,
		stringPointers: []int{},
	}

}

func ParseDNSMessage(message []byte) (DNSMessage, error) {
	if len(message) < 12 {
		return DNSMessage{}, ErrorTruncatedDNS
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
