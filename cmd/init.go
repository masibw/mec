package cmd

import (
	"github.com/masibw/mec/pkg/container"
	"github.com/urfave/cli/v2"
)

func InitCommand()*cli.Command{
	return &cli.Command{
		Name:                   "init",
		Usage:"initialize the namespaces and launch the process (do not call it outside of mec)",
		Action: func(context *cli.Context) error{
			if err:= container.Initialization(); err != nil {
				panic(err)
			}
			return nil
		},
	}
}
