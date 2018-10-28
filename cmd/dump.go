package cmd

import (
	"log"
	"time"

	"github.com/p47t/adafruit-ble-sniffer-golang/sniffer"
	"github.com/spf13/cobra"
)

// dumpCmd represents the dump command
var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump packets",
	Long:  `Dump packets`,
	Run: func(cmd *cobra.Command, args []string) {
		s := sniffer.NewSniffer(portName)
		defer s.Close()

		if dumpRawInput, _ := cmd.Flags().GetBool("raw"); dumpRawInput {
			var p = make([]byte, 1024)
			for {
				_, err := s.ReadRaw(p)
				if err != nil {
					log.Printf("failed to read: %v", err)
					return
				}
			}
		} else {
			for {
				p, err := s.WaitForPacket(sniffer.EVENT_PACKET, 1*time.Second)
				if err != nil {
					log.Printf("failed to read: %v", err)
					continue
				}
				h := &p.StaticHeader
				log.Printf("HeaderLen: %d, PayloadLen: %d, ProtoVer: %d, PacketCount: %d, id: %d",
					h.Len, h.PayloadLen, h.ProtoVer, h.PacketCount, h.Id)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(dumpCmd)
	dumpCmd.Flags().Bool("raw", false, "Dump raw data (for debugging)")
}
