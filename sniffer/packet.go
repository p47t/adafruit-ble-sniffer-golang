package sniffer

import (
	"fmt"
	"log"

	"github.com/davecgh/go-spew/spew"
)

type StaticHeader struct {
	Len         byte
	PayloadLen  byte
	ProtoVer    byte
	PacketCount int
	Id          byte
}

const (
	BLE_ADV_IND         = 0
	BLE_ADV_DIRECT_IND  = 1
	BLE_ADV_NONCONN_IND = 2
	BLE_SCAN_REQ        = 3
	BLE_SCAN_RSP        = 4
	BLE_CONNECT_REQ     = 5
	BLE_ADV_SCAN_IDN    = 6
)

type BlePacket struct {
	AccessAddr []byte
	AdvType    byte
	TxAddType  byte
	RxAddType  byte
	AdvDataLen byte
	AdvData    []byte
	CRC        int

	AdvAddr []byte
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

type ScanResponse struct {
}

type FollowResponse struct {
}

type Packet struct {
	Len int
	StaticHeader
	*EventPacketHeader
	*PingResponse
	*ScanResponse
	*FollowResponse
	RawBytes []byte
}

func parsePacket(p []byte) (*Packet, error) {
	h := Packet{
		Len: len(p),
		StaticHeader: StaticHeader{
			Len:        p[0],
			PayloadLen: p[1],
			ProtoVer:   p[2],
		},
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

	switch h.Id {
	case EVENT_PACKET:
		h.EventPacketHeader = &EventPacketHeader{
			Len:          p[6],
			Flags:        p[7],
			Channel:      p[8],
			RSSI:         p[9],
			EventCounter: int(p[10]) | int(p[11])<<8,
			Timestamp:    int(p[12]) | int(p[13])<<8 | int(p[14])<<16 | int(p[15])<<24,
		}

		// The hardware adds a padding byte which isn't sent on air.
		// The following removes it.
		p[1] -= 1
		h.PayloadLen -= 1
		copy(p[22:len(p)-1], p[23:len(p)])

		h.EventPacketHeader.BlePacket = parseBlePacket(p[16 : 16+h.PayloadLen-h.EventPacketHeader.Len])

	case EVENT_CONNECT:
	case EVENT_DEVICE:
	case EVENT_DISCONNECT:
	case EVENT_EMPTY_DATA_PACKET:
	case EVENT_ERROR:
	case PING_RESP:
		h.PingResponse = &PingResponse{
			FirmwareVersion: int(p[6]) | int(p[7])<<8,
		}
	case RESP_SCAN_CONT:
		h.ScanResponse = &ScanResponse{}
	}

	h.RawBytes = p[0 : h.StaticHeader.Len+h.StaticHeader.PayloadLen]
	return &h, nil
}

func parseBlePacket(p []byte) *BlePacket {
	l := len(p)

	blep := &BlePacket{
		AccessAddr: p[0:4],
		AdvType:    p[4] & 0x0f,
		TxAddType:  p[4] & 0x40,
		RxAddType:  p[4] & 0x80,
	}

	switch blep.AdvType {
	case BLE_ADV_IND, BLE_ADV_DIRECT_IND, BLE_ADV_NONCONN_IND, BLE_SCAN_RSP, BLE_ADV_SCAN_IDN:
		if len(p) >= 12 {
			blep.AdvDataLen = p[5]
			blep.AdvData = p[6 : l-3]
			blep.CRC = int(p[l-3]) | int(p[l-2])<<8 | int(p[l-1])<<16
			blep.AdvAddr = p[6:12]
		} else {
			log.Printf("Unexpected length for AdvType %d", blep.AdvType)
			spew.Dump(p)
		}
	case BLE_SCAN_REQ, BLE_CONNECT_REQ:
		if len(p) >= 18 {
			blep.AdvAddr = p[12:18]
		} else {
			log.Printf("Unexpected length for AdvType %d", blep.AdvType)
			spew.Dump(p)
		}
	}
	return blep
}
