package container

import (
	"errors"
	"fmt"
	"github.com/masibw/mec/pkg/configs"
	"github.com/masibw/mec/pkg/factory"
	"github.com/masibw/mec/pkg/runner"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

type CtAct uint8

var errEmptyID = errors.New("container id cannot be empty")

const (
	CT_ACT_CREATE CtAct = iota + 1
	CT_ACT_RUN
	CT_ACT_RESTORE
)


type Container interface{
	ID() string
}

type linuxContainer struct {
	id string
}

func (l *linuxContainer) ID() string{
	return l.id
}

func Start(context *cli.Context, spec *specs.Spec, action CtAct)(statusCode int, err error){
	id := context.Args().First()
	if id == ""{
		return -1, errEmptyID
	}
	//TODO notifySocket


	container, err := create(context, id, spec)
	if err != nil {
		return -1, err
	}


	//	runnerの作成
	r := &runner.Runner{
		init: true,

	}

	// 今までの設定を元にrunc initプロセスを実行する
	return r.run(spec.Process)
}

func create(context *cli.Context, id string, spec *specs.Spec) (Container, error){
	//TODO rootless cgroupについて対応

	config, err := configs.ConvertFromSpec(&configs.CreateOpts{
		CgroupName: id,
		UseSystemdCgroup: true,
		NoPivotRoot: context.Bool("no-pivot"),
		NoNewKeyring: context.Bool("no-new-keyring"),
		Spec: spec,
	})

	if err != nil {
		return nil, err
	}

	factory, err := factory.New(context)
	if err := nil {
		return nil, err
	}
	return factory.Create(id, config)
}
