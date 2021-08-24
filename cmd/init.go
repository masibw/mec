package cmd

import (
	"log"

	"github.com/masibw/mec/pkg/factory"
	"github.com/urfave/cli/v2"
)

func InitCommand() *cli.Command {
	return &cli.Command{
		Name:  "init",
		Usage: "init a container",
		Action: func(context *cli.Context) error {
			factory, err := factory.New("", "")
			if err != nil {
				log.Fatal(err)
			}
			id := context.Args().First()
			factory.Id = id
			if err := factory.Initialize(); err != nil {
				log.Fatal(err)
			}

			return nil
		},
	}
}
