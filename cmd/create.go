package cmd

import (
	"log"

	"github.com/masibw/mec/pkg/container"
	"github.com/masibw/mec/pkg/factory"
	"github.com/urfave/cli/v2"
)

func CreateCommand() *cli.Command {
	return &cli.Command{
		Name:  "create",
		Usage: "create a container",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "bundle, b",
				Value: "",
				Usage: `path to the root of the bundle directory, defaults to the current directory`,
			},
		},
		Action: func(context *cli.Context) error {
			id := context.Args().First()
			factory, err := factory.New(id, "")
			if err != nil {
				log.Fatal(err)
			}

			config, err := container.NewConfig(id, context.String("bundle"))
			if err != nil {
				log.Fatal(err)
			}

			_, err = factory.Create(config)
			if err != nil {
				log.Fatal(err)
			}

			return nil
		},
	}
}
