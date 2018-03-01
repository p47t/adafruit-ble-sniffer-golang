package cmd

import (
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"
	"github.com/yinghau76/adafruit-ble-sniffer-golang/bluetooth"
	"github.com/yinghau76/adafruit-ble-sniffer-golang/pcap"
	"github.com/yinghau76/adafruit-ble-sniffer-golang/sniffer"
)

// captureCmd represents the capture command
var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Capture packets",
	Long:  `Capture packets into specified file format`,
	Run: func(cmd *cobra.Command, args []string) {
		captureOutput, _ := cmd.Flags().GetString("output")
		log.Printf("capture to %s", captureOutput)

		w, err := pcap.NewPcapWriter(captureOutput)
		if err != nil {
			log.Printf("failed to capture: %v", err)
			return
		}
		defer w.Close()

		s := sniffer.NewSniffer(portName)
		defer s.Close()

		deviceToFollow, _ := cmd.Flags().GetString("follow")
		if len(deviceToFollow) > 0 {
			addr := bluetooth.NewAddress(deviceToFollow)
			log.Printf("Follow %v", addr)
			s.Follow(addr)
		}

		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt)
		defer signal.Stop(interrupt)

		for {
			p, err := s.WaitForPacket(sniffer.EVENT_PACKET, 1*time.Second)
			if err != nil {
				log.Printf("failed to read packet: %v", err)
				continue
			}
			log.Printf("write packet of %d bytes", len(p.RawBytes))
			_, err = w.Write(p.RawBytes)
			if err != nil {
				log.Printf("failed to write packet: %v", err)
				return
			}

			select {
			case <-interrupt:
				log.Printf("interrupted by user")
				return
			default:
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(captureCmd)
	captureCmd.Flags().StringP("output", "o", "capture.pcap", "Capture filename")
	captureCmd.Flags().StringP("follow", "f", "", "Device to follow")
}
