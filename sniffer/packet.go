package sniffer

import "fmt"

type StaticHeader struct {
	Len         byte
	PayloadLen  byte
	ProtoVer    byte
	PacketCount int
	Id          byte
}

const (
	ADV_IND         = 0
	ADV_DIRECT_IND  = 1
	ADV_NONCONN_IND = 2
	SCAN_REQ        = 3
	SCAN_RSP        = 4
	CONNECT_REQ     = 5
	ADV_SCAN_IDN    = 6
)

type BlePacket struct {
	AccessAddr []byte
	AdvType    byte
	TxAddType  byte
	RxAddType  byte

	Data    []byte
	AdvAddr []byte

	CRC int
}

func parseBlePacket(p []byte) *BlePacket {
	blep := &BlePacket{
		AccessAddr: append([]byte{}, p[0:4]...),
		AdvType:    p[4] & 0x0f,
		TxAddType:  p[4] & 0x40,
		RxAddType:  p[4] & 0x80,
		Data:       append([]byte{}, p[5:len(p)-3]...),
		// TODO: CRC
	}
	switch blep.AdvType {
	case ADV_IND, ADV_DIRECT_IND, ADV_NONCONN_IND, SCAN_RSP, ADV_SCAN_IDN:
		blep.AdvAddr = append([]byte{}, p[6:12]...)
	case SCAN_REQ, CONNECT_REQ:
		blep.AdvAddr = append([]byte{}, p[12:18]...)
	}
	return blep
}

type EventPacketHeader struct {
	Len          byte
	Flags        byte
	Channel      byte
	RSSI         byte
	EventCounter int
	Timestamp    int
	BlePacket    *BlePacket
}

type PingResponse struct {
	FirmwareVersion int
}

type Packet struct {
	Len int
	StaticHeader
	*EventPacketHeader
	*PingResponse
}

func parsePacket(p []byte) (*Packet, error) {
	h := Packet{
		len(p),
		StaticHeader{
			Len:        p[0],
			PayloadLen: p[1],
			ProtoVer:   p[2],
		},
		nil,
		nil,
	}
	if h.StaticHeader.Len != 6 {
		return nil, fmt.Errorf("invalid packet (header len = %d)", h.Len)
	}

	h.PacketCount = int(p[3]) | int(p[4])<<8
	h.Id = p[5]
	if h.Len != int(h.StaticHeader.Len)+int(h.StaticHeader.PayloadLen) {
		return nil, fmt.Errorf("invalid packet: Len = %d, Len = %d, PayloadLen = %d",
			h.Len, h.StaticHeader.Len, h.StaticHeader.PayloadLen)
	}

	switch (h.Id) {
	case EVENT_PACKET:
		h.EventPacketHeader = &EventPacketHeader{
			Len:          p[6],
			Flags:        p[7],
			Channel:      p[8],
			RSSI:         p[9],
			EventCounter: int(p[10]) | int(p[11])<<8,
			Timestamp:    int(p[12]) | int(p[13])<<8 | int(p[15])<<16 | int(p[16])<<24,
			BlePacket:    parseBlePacket(p[17:]),
		}
	case EVENT_CONNECT:
	case EVENT_DEVICE:
	case EVENT_DISCONNECT:
	case EVENT_EMPTY_DATA_PACKET:
	case EVENT_ERROR:
	case PING_RESP:
		h.PingResponse = &PingResponse{
			FirmwareVersion: int(p[6]) | int(p[7]) << 8,
		}
	}

	return &h, nil
}
