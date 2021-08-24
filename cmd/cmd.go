package cmd

import (
	"os"

	"github.com/urfave/cli/v2"
)

const (
	appName  = "mec"
	appUsage = "Self made container runtime by masibw"
)

func Run(args []string) {
	app := cli.NewApp()
	app.Name = appName
	app.Usage = appUsage
	app.Flags = []cli.Flag{
		&cli.BoolFlag{
			Name:  "debug",
			Usage: "enable debug output for logging",
		},
	}

	app.Commands = []*cli.Command{
		CreateCommand(),
		InitCommand(),
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
