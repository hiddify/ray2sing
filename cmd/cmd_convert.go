package main

import (
	"fmt"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var commandConvert = &cobra.Command{
	Use:   "convert",
	Short: "Convert link to sing-box outbound",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := convert(args[0])
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	mainCommand.AddCommand(commandConvert)
}

func convert(link string) error {
	outbound, err := ray2sing.Ray2Singbox(link)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", outbound)
	return err
}
