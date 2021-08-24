package factory

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/masibw/mec/pkg/spec"

	"github.com/masibw/mec/pkg/container"
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

const (
	rootPath = "/run/mec"
	fifoName = "fifo.exe"
)

// Factory is a producer of containers
type Factory struct {
	Id       string
	Pid      int
	Root     string
	InitPath string
	InitArgs []string
}

func New(id string, root string) (*Factory, error) {
	if root != "" {
		if err := os.MkdirAll(root, 0700); err != nil {
			return nil, err
		}
	} else {
		root = rootPath
	}

	factory := &Factory{
		Id:       id,
		Pid:      -1,
		Root:     root,
		InitPath: "/proc/self/exe",
		InitArgs: []string{os.Args[0], "init", id},
	}
	return factory, nil
}

func (f *Factory) Create(config *container.Config) (*container.Container, error) {
	containerRootPath := filepath.Join(f.Root, f.Id)
	if _, err := os.Stat(containerRootPath); !os.IsNotExist(err) {
		return nil, xerrors.Errorf("container root dir is already exist")
	}
	if err := os.MkdirAll(containerRootPath, 0711); err != nil {
		return nil, xerrors.Errorf("failed to create dir path: %s, err: %w", containerRootPath, err)
	}
	if err := os.Chown(containerRootPath, unix.Getuid(), unix.Getgid()); err != nil {
		return nil, xerrors.Errorf("failed to chown path: %s, err: %w", containerRootPath, err)
	}

	if err := os.Chdir(config.Bundle); err != nil {
		return nil, xerrors.Errorf("failed to chdir path: %s, err: %w", config.Bundle, err)
	}

	if err := f.create(); err != nil {
		return nil, xerrors.Errorf("failed to create: %w", err)
	}

	return &container.Container{
		Id:     f.Id,
		Root:   containerRootPath,
		Config: config,
	}, nil
}

func (f *Factory) create() error {
	if err := f.createFifo(); err != nil {
		return err
	}
	cmd := f.buildInitCommand()
	fd, err := f.setFifoFd(cmd)
	if err != nil {
		return err
	}

	pid, err := f.exec(cmd)
	if err != nil {
		return err
	}
	f.Pid = pid
	if _, err := os.Stat(fmt.Sprintf("/proc/self/fd/%d", fd)); err != nil {
		return err
	}
	return nil
}

func (f *Factory) createFifo() error {
	path := filepath.Join(f.Root, f.Id, fifoName)
	if _, err := os.Stat(path); err == nil {
		return xerrors.New(fmt.Sprintf("%s", fifoName) + "already exists")
	}
	if err := unix.Mkfifo(path, 0744); err != nil {
		return xerrors.Errorf("failed to create fifo file: %w", err)
	}
	return nil
}

func (f *Factory) buildInitCommand() *exec.Cmd {
	cmd := exec.Command(f.InitPath, f.InitArgs[1:]...)
	cmd.SysProcAttr = &unix.SysProcAttr{
		Cloneflags: unix.CLONE_NEWIPC | unix.CLONE_NEWNET | unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWUSER | unix.CLONE_NEWUTS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func (f *Factory) setFifoFd(cmd *exec.Cmd) (int, error) {
	path := filepath.Join(f.Root, f.Id, fifoName)
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	//TODO ここでcloseして良いのか？
	//defer unix.Close(fd)
	cmd.ExtraFiles = append(cmd.ExtraFiles, os.NewFile(uintptr(fd), fifoName))
	cmd.Env = append(cmd.Env, fmt.Sprintf("_MYCON_FIFOFD=%v", fd+3+len(cmd.ExtraFiles)-1))
	return fd, err
}

func (f *Factory) exec(cmd *exec.Cmd) (int, error) {
	if err := cmd.Start(); err != nil {
		return -1, err
	}
	pid := cmd.Process.Pid

	return pid, nil
}

func (f *Factory) Initialize() error {
	fd := os.Getenv("_MYCON_FIFOFD")
	if fd == "" {
		return xerrors.New("fd to fifo.exe [_MYCON_FIFOFD] is not set.")
	}
	fifoFd, err := strconv.Atoi(fd)
	if err != nil {
		return err
	}
	s, err := spec.LoadSpec(".")
	if err != nil {
		return err
	}
	initer, err := container.NewInitializer(s, fifoFd, f.Id)
	if err != nil {
		return err
	}
	return initer.Init()
}
