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

		scanSeconds, _ := cmd.Flags().GetDuration("duration")
		log.Printf("scanning devices for %v", scanSeconds)
		devices, err := s.ScanDevices(scanSeconds)
		if err != nil {
			log.Printf("failed to scan device: %v", err)
			return
		}
		log.Printf("found %d devices:", len(devices))
		for i, dev := range devices {
			log.Printf("#%d: %s RSSI=-%d", i, dev.Name, dev.RSSI)
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().DurationP("duration", "d", 5*time.Second, `such as "5s" or "1m"`)
}
