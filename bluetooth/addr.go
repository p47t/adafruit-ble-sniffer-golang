package bluetooth

import "fmt"

type Address []byte

func NewAddress(addr string) Address {
	a := make([]byte, 6)
	fmt.Sscanf(addr, "%x:%x:%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5])
	return a
}

func NewBigEndianAddress(addr []byte) Address {
	return []byte{addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]}
}

func (a Address) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		a[0], a[1], a[2], a[3], a[4], a[5])
}
