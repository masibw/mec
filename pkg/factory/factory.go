package factory

import (
	"github.com/masibw/mec/pkg/cgroups"
	"github.com/masibw/mec/pkg/configs"
	"github.com/masibw/mec/pkg/container"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runc/libcontainer/configs/validate"
	"github.com/opencontainers/runc/libcontainer/intelrdt"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
	"os/exec"
	"path/filepath"
)

type Factory interface{
	Create(id string, confi configs.Config) container.Container
}

type LinuxFactory struct {
	// Root directory for the factory to store state.
	Root string

	// InitPath is the path for calling the init responsibilities for spawning
	// a container.
	InitPath string

	// InitArgs are arguments for calling the init responsibilities for spawning
	// a container.
	InitArgs []string

	// CriuPath is the path to the criu binary used for checkpoint and restore of
	// containers.
	CriuPath string

	// New{u,g}idmapPath is the path to the binaries used for mapping with
	// rootless containers.
	NewuidmapPath string
	NewgidmapPath string

	// Validator provides validation to container configurations.
	Validator validate.Validator

	// NewCgroupsManager returns an initialized cgroups manager for a single container.
	NewCgroupsManager func(config *configs.Cgroup, paths map[string]string) cgroups.Manager

	// NewIntelRdtManager returns an initialized Intel RDT manager for a single container.
	NewIntelRdtManager func(config *configs.Config, id string, path string) intelrdt.Manager
}

func (f *LinuxFactory) Create(id string, config configs.Config) container.Container {

}

func New(context *cli.Context) (factory *Factory, err error){
	root := context.String("root")
	abs , err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	cgroupManager := cgroups.Cgroupfs

	if context.Bool("systemd-cgroup") {
		if !systemd.IsRunningSystemd() {
			return nil, xerrors.New("systemd cgroup flag passed, but systemd support for managing cgroups is not available")
		}
		cgroupManager = cgroups.SystemdCgroups
	}


	intelRdtManager := Intelrdtfs

	// We resolve the paths for {newuidmap,newgidmap} from the context of runc,
	// to avoid doing a path lookup in the nsexec context. TODO: The binary
	// names are not currently configurable.
	newuidmap, err := exec.LookPath("newuidmap")
	if err != nil {
		newuidmap = ""
	}
	newgidmap, err := exec.LookPath("newgidmap")
	if err != nil {
		newgidmap = ""
	}

	// runc自体をinitpathとして持ち， runc initを実行するのと同じ
	return libcontainer.New(abs, cgroupManager, intelRdtManager,
		libcontainer.CriuPath(context.GlobalString("criu")),
		libcontainer.NewuidmapPath(newuidmap),
		libcontainer.NewgidmapPath(newgidmap))
}