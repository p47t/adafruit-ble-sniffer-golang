package sniffer

import (
	"bytes"
	"text/template"

	"github.com/yinghau76/adafruit-ble-sniffer-golang/ble"
)

// Device represents a remote device discovered by scanning
type Device struct {
	Address   ble.Address
	TxAddType byte
	Name      string
	RSSI      byte
}

func (d *Device) StringTpl(tpl *template.Template) string {
	var info bytes.Buffer
	tpl.Execute(&info, d)
	return info.String()
}

// NewDevice creates a new device by inspecting information in a sniffed packet
func NewDevice(p *Packet) *Device {
	if p == nil {
		return nil
	}

	switch packet := p.BlePacket.(type) {
	case *BleAdvPacket:
		if packet == nil || len(packet.AdvAddr) == 0 {
			return nil
		}
		addr := ble.NewBigEndianAddress(packet.AdvAddr)
		dev := &Device{
			Address:   addr,
			TxAddType: packet.TxAddType,
			Name:      ble.Address(addr).String(),
			RSSI:      p.RSSI,
		}
		return dev
	case *BleDataPacket:
		return nil
	}
	return nil
}
