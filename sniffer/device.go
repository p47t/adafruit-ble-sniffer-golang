package sniffer

import "github.com/yinghau76/adafruit-ble-sniffer-golang/bluetooth"

// Device represents a remote device discovered by scanning
type Device struct {
	Address   bluetooth.Address
	TxAddType byte
	Name      string
	RSSI      byte
}

// NewDevice creates a new device by inspecting information in a sniffed packet
func NewDevice(p *Packet) *Device {
	if p == nil || p.BlePacket == nil || len(p.BlePacket.AdvAddr) == 0 {
		return nil
	}

	addr := bluetooth.NewBigEndianAddress(p.BlePacket.AdvAddr)
	return &Device{
		Address:   addr,
		TxAddType: p.BlePacket.TxAddType,
		Name:      bluetooth.Address(addr).String(),
		RSSI:      p.RSSI,
	}
}
