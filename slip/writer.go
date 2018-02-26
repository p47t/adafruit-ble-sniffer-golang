package slip

import (
	"bufio"
	"io"
)

type SlipWriter struct {
	wr *bufio.Writer
}

func NewSlipWriter(wr io.Writer) *SlipWriter {
	return &SlipWriter{bufio.NewWriter(wr)}
}

func (w *SlipWriter) Write(p []byte) (n int, err error) {
	for _, b := range p {
		switch b {
		case SLIP_START:
			w.wr.WriteByte(SLIP_ESC)
			w.wr.WriteByte(SLIP_ESC_START)
		case SLIP_END:
			w.wr.WriteByte(SLIP_ESC)
			w.wr.WriteByte(SLIP_ESC_END)
		case SLIP_ESC:
			w.wr.WriteByte(SLIP_ESC)
			w.wr.WriteByte(SLIP_ESC_ESC)
		default:
			w.wr.WriteByte(b)
		}
	}
	return len(p), nil
}


