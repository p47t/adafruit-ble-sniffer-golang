package sniffer

type Device struct {
	Address []byte
}

func NewDevice(p *Packet) *Device {
	if p == nil || p.BlePacket == nil || len(p.BlePacket.AdvAddr) == 0 {
		return nil
	}

	return &Device{
		Address: p.BlePacket.AdvAddr,
	}
}
