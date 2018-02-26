package slip

const (
	SLIP_START     = 0xAB
	SLIP_END       = 0xBC
	SLIP_ESC       = 0xCD
	SLIP_ESC_START = SLIP_START + 1
	SLIP_ESC_END   = SLIP_END + 1
	SLIP_ESC_ESC   = SLIP_ESC + 1
)
