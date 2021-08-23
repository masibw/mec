package runner

import (
	"errors"
	"fmt"
	"github.com/masibw/mec/pkg/configs"
	"github.com/masibw/mec/pkg/container"
	"github.com/opencontainers/runtime-spec/specs-go"
	"log"
	"strconv"
)

type Runner struct {
	shouldDestroy bool
	container container.Container
	detach          bool
	Init bool
	logLevel        string
	Action container.CtAct
}


// 以下のようにコンテナが実行される
//① :現在実行中(runner.run)のrunc creareプロセス:コンテナ生成フローを最上位で制御
//② :①に実行されたrunc init親プロセス(nsexec):runc creareとの中継ぎや子プロセスの同期を行う中間管理職のようなプロセス。
//③ :②に実行されたrunc init子プロセス(nsexec):実際にnamespaceを設定
//④ :③に実行されたrunc init孫プロセス(nsexec(c言語)→go言語→コンテナ(exec)):②と③が役目を終えてexit()しても生き残り、最終的にコンテナとプロセスになる。
func (r *Runner) run(config *specs.Process) (int, error) {
	var err error
	defer func() {
		if err != nil {
			r.destroy()
		}
	}()
	if err = r.checkTerminal(config); err != nil {
		return -1, err
	}
	// libcontainer.Processを作成する． r.initは新しく作成されたプロセスをinitプロセスとするかどうか(true)
	process, err := newProcess(*config, r.Init, r.logLevel)
	if err != nil {
		return -1, err
	}
	//if len(r.listenFDs) > 0 {
	//	process.Env = append(process.Env, "LISTEN_FDS="+strconv.Itoa(len(r.listenFDs)), "LISTEN_PID=1")
	//	process.ExtraFiles = append(process.ExtraFiles, r.listenFDs...)
	//}
	//baseFd := 3 + len(process.ExtraFiles)
	//for i := baseFd; i < baseFd+r.preserveFDs; i++ {
	//	_, err = os.Stat("/proc/self/fd/" + strconv.Itoa(i))
	//	if err != nil {
	//		return -1, fmt.Errorf("unable to stat preserved-fd %d (of %d): %w", i-baseFd, r.preserveFDs, err)
	//	}
	//	process.ExtraFiles = append(process.ExtraFiles, os.NewFile(uintptr(i), "PreserveFD:"+strconv.Itoa(i)))
	//}
	//rootuid, err := r.container.Config().HostRootUID()
	//if err != nil {
	//	return -1, err
	//}
	//rootgid, err := r.container.Config().HostRootGID()
	//if err != nil {
	//	return -1, err
	//}
	detach := r.detach || (r.Action == container.CT_ACT_CREATE)
	// Setting up IO is a two stage process. We need to modify process to deal
	// with detaching containers, and then we get a tty after the container has
	// started.
	handler := newSignalHandler(r.enableSubreaper, r.notifySocket)
	tty, err := setupIO(process, rootuid, rootgid, config.Terminal, detach, r.consoleSocket)
	if err != nil {
		return -1, err
	}
	defer tty.Close()


	switch r.action {
	case CT_ACT_CREATE:
		//2の親プロセスが作られる
		err = r.container.Start(process)
	case CT_ACT_RESTORE:
		err = r.container.Restore(process, r.criuOpts)
	case CT_ACT_RUN:
		err = r.container.Run(process)
	default:
		panic("Unknown action")
	}
	if err != nil {
		return -1, err
	}
	if err = tty.waitConsole(); err != nil {
		r.terminate(process)
		return -1, err
	}
	if err = tty.ClosePostStart(); err != nil {
		r.terminate(process)
		return -1, err
	}
	if r.pidFile != "" {
		if err = createPidFile(r.pidFile, process); err != nil {
			r.terminate(process)
			return -1, err
		}
	}
	status, err := handler.forward(process, tty, detach)
	if err != nil {
		r.terminate(process)
	}
	if detach {
		return 0, nil
	}
	if err == nil {
		r.destroy()
	}
	return status, err
}


func (r *Runner) destroy() {
	if r.shouldDestroy {
		destroy(r.container)
	}
}

func destroy(container container.Container) {
	if err := container.Destroy(); err != nil {
		log.Fatal(err)
	}
}


func (r *Runner) checkTerminal(config *specs.Process) error {
	detach := r.detach || (r.action == CT_ACT_CREATE)
	// Check command-line for sanity.
	if detach && config.Terminal && r.consoleSocket == "" {
		return errors.New("cannot allocate tty if runc will detach without setting console socket")
	}
	if (!detach || !config.Terminal) && r.consoleSocket != "" {
		return errors.New("cannot use console socket if runc will not detach or allocate tty")
	}
	return nil
}


// newProcess returns a new libcontainer Process with the arguments from the
// spec and stdio from the current process.
// libcontainer.Processはほとんど spec.Process由来のもの
func newProcess(p specs.Process, init bool, logLevel string) (*libcontainer.Process, error) {
	lp := &libcontainer.Process{
		Args: p.Args,
		Env:  p.Env,
		// TODO: fix libcontainer's API to better support uid/gid in a typesafe way.
		User:            fmt.Sprintf("%d:%d", p.User.UID, p.User.GID),
		Cwd:             p.Cwd,
		Label:           p.SelinuxLabel,
		NoNewPrivileges: &p.NoNewPrivileges,
		AppArmorProfile: p.ApparmorProfile,
		Init:            init,
		LogLevel:        logLevel,
	}

	if p.ConsoleSize != nil {
		lp.ConsoleWidth = uint16(p.ConsoleSize.Width)
		lp.ConsoleHeight = uint16(p.ConsoleSize.Height)
	}

	if p.Capabilities != nil {
		lp.Capabilities = &configs.Capabilities{}
		lp.Capabilities.Bounding = p.Capabilities.Bounding
		lp.Capabilities.Effective = p.Capabilities.Effective
		lp.Capabilities.Inheritable = p.Capabilities.Inheritable
		lp.Capabilities.Permitted = p.Capabilities.Permitted
		lp.Capabilities.Ambient = p.Capabilities.Ambient
	}
	for _, gid := range p.User.AdditionalGids {
		lp.AdditionalGroups = append(lp.AdditionalGroups, strconv.FormatUint(uint64(gid), 10))
	}
	for _, rlimit := range p.Rlimits {
		rl, err := createLibContainerRlimit(rlimit)
		if err != nil {
			return nil, err
		}
		lp.Rlimits = append(lp.Rlimits, rl)
	}
	return lp, nil
}
