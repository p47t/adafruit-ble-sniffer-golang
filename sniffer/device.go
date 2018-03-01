package sniffer

import (
	"fmt"
)

// Device represents a remote device discovered by scanning
type Device struct {
	Address   []byte
	TxAddType byte
	Name      string
	RSSI      byte
}

// NewDevice creates a new device by inspecting information in a sniffed packet
func NewDevice(p *Packet) *Device {
	if p == nil || p.BlePacket == nil || len(p.BlePacket.AdvAddr) == 0 {
		return nil
	}
	addr := p.BlePacket.AdvAddr
	return &Device{
		Address:   addr,
		TxAddType: p.BlePacket.TxAddType,
		Name:      fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]),
		RSSI:      p.RSSI,
	}
}
