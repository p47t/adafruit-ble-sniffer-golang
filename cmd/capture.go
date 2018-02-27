package cmd

import (
	"log"
	"time"

	"github.com/spf13/cobra"
	"github.com/yinghau76/adafruit-ble-sniffer-golang/pcap"
	"github.com/yinghau76/adafruit-ble-sniffer-golang/sniffer"
)

var captureOutput string

// captureCmd represents the capture command
var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Capture packets",
	Long:  `Capture packets into specified file format`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Printf("Capture to %s", captureOutput)

		w, err := pcap.NewPcapWriter(captureOutput)
		if err != nil {
			log.Printf("failed to capture: %v", err)
			return
		}
		defer w.Close()

		s := sniffer.NewSniffer(portName)
		defer s.Close()

		for {
			p, err := s.WaitForPacket(sniffer.EVENT_PACKET, 1*time.Second)
			if err != nil {
				log.Printf("Failed to read packet: %v", err)
				continue
			}
			log.Printf("Write packet of %d bytes", len(p.RawBytes))
			_, err = w.Write(p.RawBytes)
			if err != nil {
				log.Printf("Failed to write packet: %v", err)
				return
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(captureCmd)
	captureCmd.Flags().StringVarP(&captureOutput, "output", "o", "capture.pcap", "Capture filename")
}
