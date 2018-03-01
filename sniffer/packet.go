package sniffer

import (
	"fmt"
	"log"

	"encoding/binary"

	"github.com/davecgh/go-spew/spew"
)

type StaticHeader struct {
	Len         byte
	PayloadLen  byte
	ProtoVer    byte
	PacketCount uint16
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
	EventCounter uint16
	Timestamp    uint32
	BlePacket    *BlePacket
}

type PingResponse struct {
	FirmwareVersion uint16
}

type ScanResponse struct {
}

type FollowResponse struct {
}

type Packet struct {
	StaticHeader
	*EventPacketHeader
	*PingResponse
	*ScanResponse
	*FollowResponse
	RawBytes []byte
}

func parsePacket(p []byte) (*Packet, error) {
	h := Packet{
		StaticHeader: StaticHeader{
			Len:        p[0],
			PayloadLen: p[1],
			ProtoVer:   p[2],
		},
	}
	if h.StaticHeader.Len != 6 {
		return nil, fmt.Errorf("invalid packet (header len = %d)", h.StaticHeader.Len)
	}

	h.PacketCount = binary.LittleEndian.Uint16(p[3:5])
	h.Id = p[5]
	if len(p) != int(h.StaticHeader.Len)+int(h.StaticHeader.PayloadLen) {
		return nil, fmt.Errorf("invalid packet: Len = %d, Len = %d, PayloadLen = %d",
			len(p), h.StaticHeader.Len, h.StaticHeader.PayloadLen)
	}

	switch h.Id {
	case EVENT_PACKET:
		h.EventPacketHeader = &EventPacketHeader{
			Len:          p[6],
			Flags:        p[7],
			Channel:      p[8],
			RSSI:         p[9],
			EventCounter: binary.LittleEndian.Uint16(p[10:12]),
			Timestamp:    binary.LittleEndian.Uint32(p[12:16]),
		}

		// The hardware adds a padding byte which isn't sent on air.
		// The following removes it.
		p[1]--
		h.PayloadLen--
		copy(p[22:len(p)-1], p[23:len(p)])

		h.EventPacketHeader.BlePacket = parseBlePacket(p[16 : 16+h.PayloadLen-h.EventPacketHeader.Len])

	case EVENT_CONNECT:
	case EVENT_DEVICE:
	case EVENT_DISCONNECT:
	case EVENT_EMPTY_DATA_PACKET:
	case EVENT_ERROR:
	case PING_RESP:
		h.PingResponse = &PingResponse{
			FirmwareVersion: binary.LittleEndian.Uint16(p[6:8]),
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
			log.Printf("unexpected length for AdvType %d", blep.AdvType)
			spew.Dump(p)
		}
	case BLE_SCAN_REQ, BLE_CONNECT_REQ:
		if len(p) >= 18 {
			blep.AdvAddr = p[12:18]
		} else {
			log.Printf("unexpected length for AdvType %d", blep.AdvType)
			spew.Dump(p)
		}
	}
	return blep
}
