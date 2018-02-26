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

func (w *SlipWriter) write(p ...byte) (nn int, err error) {
	return w.wr.Write(p)
}

func (w *SlipWriter) Write(p []byte) (nn int, err error) {
	for _, b := range p {
		switch b {
		case SLIP_START:
			nn, err = w.write(SLIP_ESC, SLIP_ESC_START)
		case SLIP_END:
			nn, err = w.write(SLIP_ESC, SLIP_ESC_END)
		case SLIP_ESC:
			nn, err = w.write(SLIP_ESC, SLIP_ESC_ESC)
		default:
			nn, err = w.write(b)
		}
		if err != nil {
			return
		}
	}
	return len(p), nil
}


