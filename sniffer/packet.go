package sniffer

import "fmt"

type StaticHeader struct {
	HeaderLen   byte
	PayloadLen  byte
	ProtoVer    byte
	PacketCount int
	Id          byte
}

type Packet struct {
	StaticHeader
	Len int
}

func parsePacket(p []byte) (*Packet, error) {
	h := Packet{
		StaticHeader{
			HeaderLen:  p[0],
			PayloadLen: p[1],
			ProtoVer:   p[2],
		},
		len(p),
	}
	if h.HeaderLen == 6 {
		h.PacketCount = int(p[3]) | int(p[4])<<8
		h.Id = p[5]

		if h.Len != int(h.HeaderLen)+int(h.PayloadLen) {
			return nil, fmt.Errorf("invalid packet: Len = %d, HeaderLen = %d, PayloadLen = %d",
				h.Len, h.HeaderLen, h.PayloadLen)
		}
		return &h, nil
	}
	return nil, fmt.Errorf("invalid packet")
}
