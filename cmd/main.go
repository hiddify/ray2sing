package main

import (
	"os"
	"time"

	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var (
	disableColor bool
)

var mainCommand = &cobra.Command{
	Use:              "ray2sing",
	PersistentPreRun: preRun,
}

func init() {
	mainCommand.PersistentFlags().BoolVarP(&disableColor, "disable-color", "", false, "disable color output")
}

func main() {
	if err := mainCommand.Execute(); err != nil {
		log.Fatal(err)
	}
}

func preRun(cmd *cobra.Command, args []string) {
	if disableColor {
		log.SetStdLogger(log.NewFactory(log.Formatter{BaseTime: time.Now(), DisableColors: true}, os.Stderr, nil).Logger())
	}
}
