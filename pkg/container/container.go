package container

import (
	"errors"
	"fmt"
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

//func Start(context *cli.Context, spec *specs.Spec, action CtAct)(statusCode int, err error){
//	id := context.Args().First()
//	if id == ""{
//		return -1, errEmptyID
//	}
//
//	//TODO notifySocket
//	container, err := createContainer(context, id, spec)
//	if err != nil {
//		return -1, err
//	}
//
//
//}

func Create(context *cli.Context, spec *specs.Spec)(statusCode int, err error){
	//Rerun this program with init arg.
	cmd := exec.Command("/proc/self/exe", append([]string{"init"}, spec.Process.Args...)...)
	cmd.SysProcAttr = &unix.SysProcAttr{
			//Separate namespaces
			Cloneflags:
				unix.CLONE_NEWIPC |
				unix.CLONE_NEWNET |
				unix.CLONE_NEWNS |
				unix.CLONE_NEWPID |
				unix.CLONE_NEWUSER |
				unix.CLONE_NEWPID |
				unix.CLONE_NEWUSER |
				unix.CLONE_NEWUTS,
				//Set the uid and gid at the new namespace.
				//Automatically written to /proc/[pid]/uid_map and /proc/[pid]/gid_map.
				UidMappings: []syscall.SysProcIDMap{
					{
						ContainerID: 0,
						HostID:      os.Getuid(),
						Size:        1,
					},
				},
				GidMappings: []syscall.SysProcIDMap{
					{
						ContainerID: 0,
						HostID:      os.Getgid(),
						Size:        1,
					},
				},
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err = cmd.Run(); err != nil {
		return cmd.ProcessState.ExitCode(), xerrors.Errorf("failed to run command: %w", err)
	}
	return
}

func Initialization() (err error){
	fmt.Printf("Running init %v \n", os.Args[2:])

	cg()

	cmd := exec.Command(os.Args[2], os.Args[3:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// hostnameを設定 ユーザー名@ホスト名 ってやつ
	must(unix.Sethostname([]byte("container-masi")))
	// 子プロセスのルートを / に指定
	must(unix.Chroot("/"))
	// ワーキングディレクトリを / に
	must(os.Chdir("/"))

	//
	must(unix.Mount("proc", "proc", "proc", 0, ""))
	must(cmd.Run())

	must(unix.Unmount("proc",0))
	return nil
}

func cg(){
	cgroups := "/sys/fs/cgroup/"
	pids := filepath.Join(cgroups, "pids")
	os.Mkdir(filepath.Join(pids, "masi"), 0755)

	// cgroupの設定をしていく https://access.redhat.com/documentation/ja-jp/red_hat_enterprise_linux/6/html/resource_management_guide/sec-common_tunable_parameters
	// pids.max は許可するプロセス数
	must(os.WriteFile(filepath.Join(pids, "masi/pids.max"),[]byte("20"),0700))
	// notify_on_release cgroupにタスクがなくなったときにカーネルがrelease_agentファイルの内容を実行するらしい
	must(os.WriteFile(filepath.Join(pids, "masi/notify_on_release"),[]byte("1"),0700))
	// cgroups.procs cgroupで実行中のスレッドグループの一覧が書かれている． cgroupsのtasksファイルに書き込むと，そのスレッドグループはcgroupに移動する
	must(os.WriteFile(filepath.Join(pids, "masi/cgroup.procs"), []byte(strconv.Itoa(os.Getpid())),0700))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
