package cmd

import (
	"log"
	"time"

	"github.com/spf13/cobra"
	"github.com/yinghau76/adafruit-ble-sniffer-golang/sniffer"
)

var scanSeconds int32

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan BLE devices",
	Long:  `Scan BLE devices for specified duration`,
	Run: func(cmd *cobra.Command, args []string) {
		s := sniffer.NewSniffer(portName)
		defer s.Close()

		log.Printf("scanning devices (%d s)...", scanSeconds)
		devices, err := s.ScanDevices(time.Duration(scanSeconds) * time.Second)
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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// scanCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	scanCmd.Flags().Int32VarP(&scanSeconds, "duration", "d", 5, "in seconds")
}
