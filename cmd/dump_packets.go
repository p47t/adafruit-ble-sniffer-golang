package main

import (
	"log"
	"github.com/yinghau76/adafruit-ble-sniffer-golang/sniffer"
	"time"
)

func main() {
	s := sniffer.NewSniffer()
	defer s.Close()

	log.Printf("Scanning devices (5s)...")
	devices, _ := s.ScanDevices(5 * time.Second)
	log.Printf("Found %d devices", len(devices))

	for {
		p, err := s.WaitForPacket(sniffer.EVENT_PACKET, 1 * time.Second)
		if err != nil {
			log.Printf("Failed to read: %v", err)
			continue
		}
		h := &p.StaticHeader
		log.Printf("HeaderLen: %d, PayloadLen: %d, ProtoVer: %d, PacketCount: %d, id: %d", h.Len, h.PayloadLen, h.ProtoVer, h.PacketCount, h.Id)
	}
}
