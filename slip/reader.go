package slip

import (
	"bufio"
	"io"
)

type SlipReader struct {
	rd *bufio.Reader
}

func NewSlipReader(rd io.Reader) *SlipReader {
	return &SlipReader{bufio.NewReader(rd)}
}

func (r *SlipReader) Read(packet []byte) (n int, err error) {
	i := 0
	for {
		b, err := r.rd.ReadByte()
		if err != nil {
			return i, err
		}
		if b == SLIP_START {
			break
		}
	} // sync to start
	for {
		b, err := r.rd.ReadByte()
		if err != nil {
			return i, err
		}
		if b == SLIP_END {
			return i, nil
		}

		if b == SLIP_ESC {
			escaped, err := r.rd.ReadByte()
			if err != nil {
				return i, err
			}
			switch escaped {
			case SLIP_ESC_START:
				packet[i] = SLIP_START
			case SLIP_ESC_END:
				packet[i] = SLIP_END
			case SLIP_ESC_ESC:
				packet[i] = SLIP_ESC
			default:
				packet[i] = SLIP_END
			}
		} else {
			packet[i] = b
		}
		i++
	}
}
