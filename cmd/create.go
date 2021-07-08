package cmd

import (
	"fmt"
	"github.com/urfave/cli/v2"
)

func CreateCommand() *cli.Command {
	return &cli.Command{
		Name:  "create",
		Usage: "create a container",
		Action: func(context *cli.Context) error {
			fmt.Println("create called")
			return nil
		},
	}
}
