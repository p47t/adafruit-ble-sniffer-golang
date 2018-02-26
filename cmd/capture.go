package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var captureFormat string

// captureCmd represents the capture command
var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Capture packets",
	Long:  `Capture packets into specified file format`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Not implemented yet")
	},
}

func init() {
	rootCmd.AddCommand(captureCmd)
	captureCmd.Flags().StringVarP(&captureFormat, "format", "f", "pcap", "Capture file format")
}
