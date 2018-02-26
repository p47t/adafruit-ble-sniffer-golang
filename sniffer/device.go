package sniffer

import "fmt"

type Device struct {
	Address []byte
	Name    string
	RSSI    byte
}

func NewDevice(p *Packet) *Device {
	if p == nil || p.BlePacket == nil || len(p.BlePacket.AdvAddr) == 0 {
		return nil
	}

	addr := p.BlePacket.AdvAddr
	return &Device{
		Address: addr,
		Name:    fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]),
		RSSI:    p.RSSI,
	}
}
