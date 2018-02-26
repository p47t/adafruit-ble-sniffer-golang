package main

import (
	"log"
	"os"
	"time"

	"github.com/yinghau76/adafruit-ble-sniffer-golang/sniffer"
)

func main() {
	s := sniffer.NewSniffer(os.Args[1])
	defer s.Close()

	log.Printf("Scanning devices (5s)...")
	devices, err := s.ScanDevices(5 * time.Second)
	if err != nil {
		log.Printf("failed to scan device: %v", err)
		return
	}
	log.Printf("Found %d devices", len(devices))

	for {
		p, err := s.WaitForPacket(sniffer.EVENT_PACKET, 1*time.Second)
		if err != nil {
			log.Printf("Failed to read: %v", err)
			continue
		}
		h := &p.StaticHeader
		log.Printf("HeaderLen: %d, PayloadLen: %d, ProtoVer: %d, PacketCount: %d, id: %d", h.Len, h.PayloadLen, h.ProtoVer, h.PacketCount, h.Id)
	}
}
