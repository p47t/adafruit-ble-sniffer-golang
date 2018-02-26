package main

import (
	"log"
	"github.com/yinghau76/adafruit-ble-sniffer-golang/sniffer"
)

func main() {
	s := sniffer.NewSniffer()
	defer s.Close()

	s.Ping()
	s.Scan()

	for {
		p, err := s.ReadPacket()
		if err != nil {
			log.Printf("Failed to read: %v", err)
			continue
		}
		log.Printf("HeaderLen: %d, PayloadLen: %d, ProtoVer: %d, PacketCount: %d, id: %d",
			p.HeaderLen, p.PayloadLen, p.ProtoVer, p.PacketCount, p.Id)
	}
}
