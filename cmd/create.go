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
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "bundle, b",
				Value: "",
				Usage: `path to the root of the bundle directory, defaults to the current directory`,
			},
			&cli.StringFlag{
				Name:  "console-socket",
				Value: "",
				Usage: "path to an AF_UNIX socket which will receive a file descriptor referencing the master end of the console's pseudoterminal",
			},
			&cli.StringFlag{
				Name:  "pid-file",
				Value: "",
				Usage: "specify the file to write the process id to",
			},
			&cli.BoolFlag{
				Name:  "no-pivot",
				Usage: "do not use pivot root to jail process inside rootfs.  This should be used whenever the rootfs is on top of a ramdisk",
			},
			&cli.BoolFlag{
				Name:  "no-new-keyring",
				Usage: "do not create a new session keyring for the container.  This will cause the container to inherit the calling processes session key",
			},
			&cli.IntFlag{
				Name:  "preserve-fds",
				Usage: "Pass N additional file descriptors to the container (stdio + $LISTEN_FDS + N in total)",
			},
		},
		Action: func(context *cli.Context) error {
			fmt.Printf("args: %v\n", context.Args())

			spec, err := spec.SetupSpec(context, specConfig)
			if err != nil {
				return err
			}
			statusCode, err := container.Start(context, spec, container.CT_ACT_CREATE)
			if err != nil {
				return err
			}
			os.Exit(statusCode)
			return nil
		},
	}
}
