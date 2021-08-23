package cgroups

import (
	"github.com/masibw/mec/pkg/configs"
	"github.com/masibw/mec/pkg/factory"
	"golang.org/x/xerrors"
	"regexp"
)

var (
	idRegex      = regexp.MustCompile(`^[\w+-\.]+$`)
	errNoSystemd = xerrors.New("systemd not running on this host, can't use systemd as cgroups manager")
)

// Cgroupfs is an options func to configure a LinuxFactory to return containers
// that use the native cgroups filesystem implementation to create and manage
// cgroups.
func Cgroupfs(l *factory.LinuxFactory) error {
	return cgroupfs(l, false)
}


func cgroupfs(l *factory.LinuxFactory, rootless bool) error {
	if cgroups.IsCgroup2UnifiedMode() {
		return cgroupfs2(l, rootless)
	}
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return fs.NewManager(config, paths, rootless)
	}
	return nil
}


func cgroupfs2(l *factory.LinuxFactory, rootless bool) error {
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		m, err := fs2.NewManager(config, getUnifiedPath(paths), rootless)
		if err != nil {
			panic(err)
		}
		return m
	}
	return nil
}



// SystemdCgroups is an options func to configure a LinuxFactory to return
// containers that use systemd to create and manage cgroups.
func SystemdCgroups(l *factory.LinuxFactory) error {
	if !systemd.IsRunningSystemd() {
		return errNoSystemd
	}

	if cgroups.IsCgroup2UnifiedMode() {
		return systemdCgroupV2(l, false)
	}

	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return systemd.NewLegacyManager(config, paths)
	}

	return nil
}


func systemdCgroupV2(l *factory.LinuxFactory, rootless bool) error {
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return systemd.NewUnifiedManager(config, getUnifiedPath(paths), rootless)
	}
	return nil
}

type Manager interface {
	// Apply creates a cgroup, if not yet created, and adds a process
	// with the specified pid into that cgroup.  A special value of -1
	// can be used to merely create a cgroup.
	Apply(pid int) error

	// GetPids returns the PIDs of all processes inside the cgroup.
	GetPids() ([]int, error)

	// GetAllPids returns the PIDs of all processes inside the cgroup
	// any all its sub-cgroups.
	GetAllPids() ([]int, error)

	// GetStats returns cgroups statistics.
	GetStats() (*Stats, error)

	// Freeze sets the freezer cgroup to the specified state.
	Freeze(state configs.FreezerState) error

	// Destroy removes cgroup.
	Destroy() error

	// Path returns a cgroup path to the specified controller/subsystem.
	// For cgroupv2, the argument is unused and can be empty.
	Path(string) string

	// Set sets cgroup resources parameters/limits. If the argument is nil,
	// the resources specified during Manager creation (or the previous call
	// to Set) are used.
	Set(r *configs.Resources) error

	// GetPaths returns cgroup path(s) to save in a state file in order to
	// restore later.
	//
	// For cgroup v1, a key is cgroup subsystem name, and the value is the
	// path to the cgroup for this subsystem.
	//
	// For cgroup v2 unified hierarchy, a key is "", and the value is the
	// unified path.
	GetPaths() map[string]string

	// GetCgroups returns the cgroup data as configured.
	GetCgroups() (*configs.Cgroup, error)

	// GetFreezerState retrieves the current FreezerState of the cgroup.
	GetFreezerState() (configs.FreezerState, error)

	// Exists returns whether the cgroup path exists or not.
	Exists() bool

	// OOMKillCount reports OOM kill count for the cgroup.
	OOMKillCount() (uint64, error)
}