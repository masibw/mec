package container

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

const (
	rootPath = "/run/mec"
	fifoName = "fifo.exe"
)

type Initializer struct {
	Id     string
	FifoFd int
	Spec   *specs.Spec
	//Cgroups      *cgroups.Cgroups
	//Capabilities *capabilitiesCapabilities
}

func NewInitializer(spec *specs.Spec, fd int, id string) (*Initializer, error) {
	//cg, err := cgroups.New(spec.Linux.Resouces)
	//if err != nil {
	//	return nil, err
	//}
	//
	//var caps *capabilities.Capabilities
	//if spec.Process.Capabilities != nil {
	//	caps, err = capabilities.New(spec.Process.Capabilities)
	//	if err != nil {
	//		return nil, err
	//	}
	//}
	return &Initializer{
		Id:     id,
		FifoFd: fd,
		Spec:   spec,
		//Cgroups:      cg,
		//Capabilities: caps,
	}, nil
}

func (i *Initializer) Init() error {
	if err := i.prepareRootfs(); err != nil {
		return xerrors.Errorf("failed to prepare root fs: %w", err)
	}
	//
	//if err := i.Capabilities.ApplyCaps(); err != nil {
	//	return err
	//}

	dir, err := os.Getwd() // カレントディレクトリ情報取得
	if err != nil {
		log.Fatal(err)
	}

	fileInfos, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}

	for _, fileInfo := range fileInfos {
		fmt.Println(fileInfo.Name())
	}

	fmt.Println(os.Environ())

	name, err := exec.LookPath(i.Spec.Process.Args[0])
	if err != nil {
		return xerrors.Errorf("failed to LookPath: %s, err: %w", i.Spec.Process.Args[0], err)
	}
	if err := unix.Exec(name, i.Spec.Process.Args[0:], os.Environ()); err != nil {
		return xerrors.Errorf("failed to exec name: %s, args: %s, err: %w", name, i.Spec.Process.Args[0:])
	}
	return nil
}

func (i *Initializer) prepareRootfs() error {
	if err := i.prepareRoot(); err != nil {
		return xerrors.Errorf("failed to prepare root: %w", err)
	}

	//if err := i.Cgroups.Limit(); err != nil {
	//	return err
	//}

	if err := i.pivotRoot(); err != nil {
		return xerrors.Errorf("failed to pivot root: %w", err)
	}
	return nil
}

func (i *Initializer) prepareRoot() error {
	//rootをmountする
	if err := unix.Mount("", "/", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		return xerrors.Errorf("failed to mount: %w", err)
	}

	rcwd, err := os.Getwd()
	if err != nil {
		return err
	}
	cwd, err := filepath.Abs(rcwd)
	if err != nil {
		return err
	}
	if i.Spec.Root == nil {
		return xerrors.New("root must be specified")
	}
	// config.jsonのrootfsディレクトリを設定
	rootfsPath := i.Spec.Root.Path
	log.Println(filepath.IsAbs(rootfsPath))
	if !filepath.IsAbs(rootfsPath) {
		log.Println(cwd)
		log.Println(rootfsPath)
		log.Println(filepath.Join(cwd, rootfsPath))
		rootfsPath = filepath.Join(cwd, rootfsPath)
	}
	log.Println(rootfsPath)
	//TODO /home/masi/mec/rootfs が -> /home/masi/mec/rootfs/rootfs になっている
	// createコマンドでconfigを設定する時点で絶対パスにして，pipeでinitコマンドのプロセスへ渡したい
	if err := unix.Mount(rootfsPath, rootfsPath, "bind", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return xerrors.Errorf("failed to mount source: %s, target: %s, err: %w", rootfsPath, rootfsPath, err)
	}

	return nil
}

func (i *Initializer) pivotRoot() error {
	oldroot, err := unix.Open("/", unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return xerrors.Errorf("failed to open path: %s, err: %w", "/", err)
	}
	defer unix.Close(oldroot)
	newRoot, err := unix.Open(i.Spec.Root.Path, unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return xerrors.Errorf("failed to open path: %s, err: %w", i.Spec.Root.Path, err)
	}

	// TODO pivotRootについて理解する
	defer unix.Close(newRoot)
	if err := unix.Fchdir(newRoot); err != nil {
		return xerrors.Errorf("failed to fchdir: %w", err)
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return xerrors.Errorf("failed to pivot root: %w", err)
	}
	if err := unix.Fchdir(oldroot); err != nil {
		return err
	}
	if err := unix.Mount("", ".", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		return err
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return err
	}
	if err := unix.Chdir("/"); err != nil {
		return xerrors.Errorf("failed to chdir: %v", err)
	}
	return nil
}
