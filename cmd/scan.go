package cmd

import (
	"log"
	"time"

	"github.com/spf13/cobra"
	"github.com/yinghau76/adafruit-ble-sniffer-golang/sniffer"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan BLE devices",
	Long:  `Scan BLE devices for specified duration`,
	Run: func(cmd *cobra.Command, args []string) {
		s := sniffer.NewSniffer(portName)
		defer s.Close()

		scanDuration, _ := cmd.Flags().GetDuration("duration")
		log.Printf("scanning devices for %v", scanDuration)
		devices, err := s.ScanDevices(scanDuration)
		if err != nil {
			log.Printf("failed to scan device: %v", err)
			return
		}

	wait:
		for {
			select {
			case dev := <-devices:
				if dev == nil {
					break wait
				}
				log.Printf("found: %s RSSI=-%d", dev.Name, dev.RSSI)
			}
		}

		log.Printf("found %d devices totally:", len(s.Devices()))
		for i, dev := range s.Devices() {
			log.Printf("#%d: %s RSSI=-%d", i, dev.Name, dev.RSSI)
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().DurationP("duration", "d", 5*time.Second, `such as "5s" or "1m"`)
}
