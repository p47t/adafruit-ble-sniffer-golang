package cmd

import (
	"log"
	"text/template"
	"time"

	"github.com/p47t/adafruit-ble-sniffer-golang/sniffer"
	"github.com/spf13/cobra"
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

		format, _ := cmd.Flags().GetString("format")
		infoTpl, err := template.New("DeviceInfo").Parse(format)
		if err != nil {
			log.Printf("failed to parse format")
			return
		}
	wait:
		for {
			select {
			case dev := <-devices:
				if dev == nil {
					break wait
				}
				log.Printf("found: %s", dev.StringTpl(infoTpl))
			}
		}

		log.Printf("found %d devices totally:", len(s.Devices()))
		for i, dev := range s.Devices() {
			log.Printf("#%d: %s", i, dev.StringTpl(infoTpl))
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().DurationP("duration", "d", 5*time.Second, `such as "5s" or "1m"`)
	scanCmd.Flags().StringP("format", "f", "{{.Name}} RSSI=-{{.RSSI}}", `format string for device information`)
}
