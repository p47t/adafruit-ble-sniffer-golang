package pcap

import (
	"bufio"
	"encoding/binary"
	"os"
	"time"
)

const (
	LINKTYPE_BLUETOOTH_LE_LL = 251
	LINKTYPE_NORDIC_BLE      = 157

	MAGIC_NUMBER  = 0xa1b2c3d4
	VERSION_MAJOR = 2
	VERSION_MINOR = 4
	THISZONE      = 0
	SIGFIGS       = 0
	SNAPLEN       = 0xffff
	NETWORK       = LINKTYPE_NORDIC_BLE
)

type PcapWriter struct {
	f  *os.File
	wr *bufio.Writer
}

func NewPcapWriter(filename string) (*PcapWriter, error) {
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	bf := bufio.NewWriter(f)

	header := []interface{}{
		uint32(MAGIC_NUMBER),
		uint16(VERSION_MAJOR),
		uint16(VERSION_MINOR),
		uint32(THISZONE),
		uint32(SIGFIGS),
		uint32(SNAPLEN),
		uint32(NETWORK),
	}
	for _, v := range header {
		if err := binary.Write(bf, binary.LittleEndian, v); err != nil {
			f.Close()
			return nil, err
		}
	}

	return &PcapWriter{f, bf}, nil
}

func (w *PcapWriter) write(p ...byte) (nn int, err error) {
	return w.wr.Write(p)
}

func (w *PcapWriter) Write(p []byte) (nn int, err error) {
	now := time.Now()

	packetHeader := []interface{}{
		uint32(now.Unix()),            // TS_SEC
		uint32(now.UnixNano() / 1000), // TS_USEC
		uint32(len(p) + 1),            // INCL_LENGTH
		uint32(len(p) + 1),            // ORIG_LENGTH
		byte(0),                       // Board ID
	}
	for _, v := range packetHeader {
		if err := binary.Write(w.wr, binary.LittleEndian, v); err != nil {
			return 0, err
		}
	}
	if _, err := w.wr.Write(p); err != nil {
		return nn, err
	}
	return len(p), nil
}

func (w *PcapWriter) Close() {
	w.f.Close()
}
