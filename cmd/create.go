package cmd

import (
	"fmt"
	"github.com/masibw/mec/pkg/container"
	"github.com/masibw/mec/pkg/spec"
	"github.com/urfave/cli/v2"
	"os"
)


func CreateCommand() *cli.Command {
	return &cli.Command{
		Name:  "create",
		Usage: "create a container",
		ArgsUsage: `<container-id>`,
		Action: func(context *cli.Context) error {
			fmt.Printf("args: %v\n", context.Args())

			spec, err := spec.LoadSpec(specConfig)
			if err != nil {
				return err
			}
			statusCode, err := container.Create(context, spec)
			if err != nil {
				return err
			}
			os.Exit(statusCode)
			return nil
		},
	}
}
