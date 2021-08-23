package configs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
	"github.com/masibw/mec/pkg/devices"
	"github.com/masibw/mec/pkg/seccomp"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)



const (
	// Prestart commands are executed after the container namespaces are created,
	// but before the user supplied command is executed from init.
	// Note: This hook is now deprecated
	// Prestart commands are called in the Runtime namespace.
	Prestart HookName = "prestart"

	// CreateRuntime commands MUST be called as part of the create operation after
	// the runtime environment has been created but before the pivot_root has been executed.
	// CreateRuntime is called immediately after the deprecated Prestart hook.
	// CreateRuntime commands are called in the Runtime Namespace.
	CreateRuntime HookName = "createRuntime"

	// CreateContainer commands MUST be called as part of the create operation after
	// the runtime environment has been created but before the pivot_root has been executed.
	// CreateContainer commands are called in the Container namespace.
	CreateContainer HookName = "createContainer"

	// StartContainer commands MUST be called as part of the start operation and before
	// the container process is started.
	// StartContainer commands are called in the Container namespace.
	StartContainer HookName = "startContainer"

	// Poststart commands are executed after the container init process starts.
	// Poststart commands are called in the Runtime Namespace.
	Poststart HookName = "poststart"

	// Poststop commands are executed after the container init process exits.
	// Poststop commands are called in the Runtime Namespace.
	Poststop HookName = "poststop"
)

type Capabilities struct {
	// Bounding is the set of capabilities checked by the kernel.
	Bounding []string
	// Effective is the set of capabilities checked by the kernel.
	Effective []string
	// Inheritable is the capabilities preserved across execve.
	Inheritable []string
	// Permitted is the limiting superset for effective capabilities.
	Permitted []string
	// Ambient is the ambient set of capabilities that are kept.
	Ambient []string
}

const (
	// EXT_COPYUP is a directive to copy up the contents of a directory when
	// a tmpfs is mounted over it.
	EXT_COPYUP = 1 << iota //nolint:golint // ignore "don't use ALL_CAPS" warning
)


type Command struct {
	Path    string         `json:"path"`
	Args    []string       `json:"args"`
	Env     []string       `json:"env"`
	Dir     string         `json:"dir"`
	Timeout *time.Duration `json:"timeout"`
}

// NewCommandHook will execute the provided command when the hook is run.
func NewCommandHook(cmd Command) CommandHook {
	return CommandHook{
		Command: cmd,
	}
}

type CommandHook struct {
	Command
}


func (c Command) Run(s *specs.State) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Cmd{
		Path:   c.Path,
		Args:   c.Args,
		Env:    c.Env,
		Stdin:  bytes.NewReader(b),
		Stdout: &stdout,
		Stderr: &stderr,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	errC := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		if err != nil {
			err = fmt.Errorf("error running hook: %w, stdout: %s, stderr: %s", err, stdout.String(), stderr.String())
		}
		errC <- err
	}()
	var timerCh <-chan time.Time
	if c.Timeout != nil {
		timer := time.NewTimer(*c.Timeout)
		defer timer.Stop()
		timerCh = timer.C
	}
	select {
	case err := <-errC:
		return err
	case <-timerCh:
		_ = cmd.Process.Kill()
		<-errC
		return fmt.Errorf("hook ran past specified timeout of %.1fs", c.Timeout.Seconds())
	}
}

type Resources struct {
	// Devices is the set of access rules for devices in the container.
	Devices []*devices.Rule `json:"devices"`

	// Memory limit (in bytes)
	Memory int64 `json:"memory"`

	// Memory reservation or soft_limit (in bytes)
	MemoryReservation int64 `json:"memory_reservation"`

	// Total memory usage (memory + swap); set `-1` to enable unlimited swap
	MemorySwap int64 `json:"memory_swap"`

	// CPU shares (relative weight vs. other containers)
	CpuShares uint64 `json:"cpu_shares"`

	// CPU hardcap limit (in usecs). Allowed cpu time in a given period.
	CpuQuota int64 `json:"cpu_quota"`

	// CPU period to be used for hardcapping (in usecs). 0 to use system default.
	CpuPeriod uint64 `json:"cpu_period"`

	// How many time CPU will use in realtime scheduling (in usecs).
	CpuRtRuntime int64 `json:"cpu_rt_quota"`

	// CPU period to be used for realtime scheduling (in usecs).
	CpuRtPeriod uint64 `json:"cpu_rt_period"`

	// CPU to use
	CpusetCpus string `json:"cpuset_cpus"`

	// MEM to use
	CpusetMems string `json:"cpuset_mems"`

	// Process limit; set <= `0' to disable limit.
	PidsLimit int64 `json:"pids_limit"`

	// Specifies per cgroup weight, range is from 10 to 1000.
	BlkioWeight uint16 `json:"blkio_weight"`

	// Specifies tasks' weight in the given cgroup while competing with the cgroup's child cgroups, range is from 10 to 1000, cfq scheduler only
	BlkioLeafWeight uint16 `json:"blkio_leaf_weight"`

	// Weight per cgroup per device, can override BlkioWeight.
	BlkioWeightDevice []*devices.WeightDevice `json:"blkio_weight_device"`

	// IO read rate limit per cgroup per device, bytes per second.
	BlkioThrottleReadBpsDevice []*devices.ThrottleDevice `json:"blkio_throttle_read_bps_device"`

	// IO write rate limit per cgroup per device, bytes per second.
	BlkioThrottleWriteBpsDevice []*devices.ThrottleDevice `json:"blkio_throttle_write_bps_device"`

	// IO read rate limit per cgroup per device, IO per second.
	BlkioThrottleReadIOPSDevice []*devices.ThrottleDevice `json:"blkio_throttle_read_iops_device"`

	// IO write rate limit per cgroup per device, IO per second.
	BlkioThrottleWriteIOPSDevice []*devices.ThrottleDevice `json:"blkio_throttle_write_iops_device"`

	// set the freeze value for the process
	Freezer FreezerState `json:"freezer"`

	// Hugetlb limit (in bytes)
	HugetlbLimit []*HugepageLimit `json:"hugetlb_limit"`

	// Whether to disable OOM Killer
	OomKillDisable bool `json:"oom_kill_disable"`

	// Tuning swappiness behaviour per cgroup
	MemorySwappiness *uint64 `json:"memory_swappiness"`

	// Set priority of network traffic for container
	NetPrioIfpriomap []*IfPrioMap `json:"net_prio_ifpriomap"`

	// Set class identifier for container's network packets
	NetClsClassid uint32 `json:"net_cls_classid_u"`

	// Used on cgroups v2:

	// CpuWeight sets a proportional bandwidth limit.
	CpuWeight uint64 `json:"cpu_weight"`

	// Unified is cgroupv2-only key-value map.
	Unified map[string]string `json:"unified"`

	// SkipDevices allows to skip configuring device permissions.
	// Used by e.g. kubelet while creating a parent cgroup (kubepods)
	// common for many containers, and by runc update.
	//
	// NOTE it is impossible to start a container which has this flag set.
	SkipDevices bool `json:"-"`

	// SkipFreezeOnSet is a flag for cgroup manager to skip the cgroup
	// freeze when setting resources. Only applicable to systemd legacy
	// (i.e. cgroup v1) manager (which uses freeze by default to avoid
	// spurious permission errors caused by systemd inability to update
	// device rules in a non-disruptive manner).
	//
	// If not set, a few methods (such as looking into cgroup's
	// devices.list and querying the systemd unit properties) are used
	// during Set() to figure out whether the freeze is required. Those
	// methods may be relatively slow, thus this flag.
	SkipFreezeOnSet bool `json:"-"`
}

type FreezerState string

const (
	Undefined FreezerState = ""
	Frozen    FreezerState = "FROZEN"
	Thawed    FreezerState = "THAWED"
)

// Cgroup holds properties of a cgroup on Linux.
type Cgroup struct {
	// Name specifies the name of the cgroup
	Name string `json:"name,omitempty"`

	// Parent specifies the name of parent of cgroup or slice
	Parent string `json:"parent,omitempty"`

	// Path specifies the path to cgroups that are created and/or joined by the container.
	// The path is assumed to be relative to the host system cgroup mountpoint.
	Path string `json:"path"`

	// ScopePrefix describes prefix for the scope name
	ScopePrefix string `json:"scope_prefix"`

	// Paths represent the absolute cgroups paths to join.
	// This takes precedence over Path.
	Paths map[string]string

	// Resources contains various cgroups settings to apply
	*Resources

	// SystemdProps are any additional properties for systemd,
	// derived from org.systemd.property.xxx annotations.
	// Ignored unless systemd is used for managing cgroups.
	SystemdProps []systemdDbus.Property `json:"-"`
}

type Mount struct {
	Source           string    `json:"source"`
	Destination      string    `json:"destination"`
	Device           string    `json:"device"`
	Flags            int       `json:"flags"`
	PropagationFlags []int     `json:"propagation_flags"`
	Data             string    `json:"data"`
	Relabel          string    `json:"relabel"`
	Extensions       int       `json:"extensions"`
	PremountCmds     []Command `json:"premount_cmds"`
	PostmountCmds    []Command `json:"postmount_cmds"`
}


type Rlimit struct {
	Type int    `json:"type"`
	Hard uint64 `json:"hard"`
	Soft uint64 `json:"soft"`
}


type Config struct {
	// NoPivotRoot will use MS_MOVE and a chroot to jail the process into the container's rootfs
	// This is a common option when the container is running in ramdisk
	NoPivotRoot bool `json:"no_pivot_root"`

	// ParentDeathSignal specifies the signal that is sent to the container's process in the case
	// that the parent process dies.
	ParentDeathSignal int `json:"parent_death_signal"`

	// Path to a directory containing the container's root filesystem.
	Rootfs string `json:"rootfs"`

	// Umask is the umask to use inside of the container.
	Umask *uint32 `json:"umask"`

	// Readonlyfs will remount the container's rootfs as readonly where only externally mounted
	// bind mounts are writtable.
	Readonlyfs bool `json:"readonlyfs"`

	// Specifies the mount propagation flags to be applied to /.
	RootPropagation int `json:"rootPropagation"`

	// Mounts specify additional source and destination paths that will be mounted inside the container's
	// rootfs and mount namespace if specified
	Mounts []*Mount `json:"mounts"`

	// The device nodes that should be automatically created within the container upon container start.  Note, make sure that the node is marked as allowed in the cgroup as well!
	Devices []*devices.Device `json:"devices"`

	MountLabel string `json:"mount_label"`

	// Hostname optionally sets the container's hostname if provided
	Hostname string `json:"hostname"`

	// Namespaces specifies the container's namespaces that it should setup when cloning the init process
	// If a namespace is not provided that namespace is shared from the container's parent process
	Namespaces Namespaces `json:"namespaces"`

	// Capabilities specify the capabilities to keep when executing the process inside the container
	// All capabilities not specified will be dropped from the processes capability mask
	Capabilities *Capabilities `json:"capabilities"`

	// Networks specifies the container's network setup to be created
	Networks []*Network `json:"networks"`

	// Routes can be specified to create entries in the route table as the container is started
	Routes []*Route `json:"routes"`

	// Cgroups specifies specific cgroup settings for the various subsystems that the container is
	// placed into to limit the resources the container has available
	Cgroups *Cgroup `json:"cgroups"`

	// AppArmorProfile specifies the profile to apply to the process running in the container and is
	// change at the time the process is execed
	AppArmorProfile string `json:"apparmor_profile,omitempty"`

	// ProcessLabel specifies the label to apply to the process running in the container.  It is
	// commonly used by selinux
	ProcessLabel string `json:"process_label,omitempty"`

	// Rlimits specifies the resource limits, such as max open files, to set in the container
	// If Rlimits are not set, the container will inherit rlimits from the parent process
	Rlimits []Rlimit `json:"rlimits,omitempty"`

	// OomScoreAdj specifies the adjustment to be made by the kernel when calculating oom scores
	// for a process. Valid values are between the range [-1000, '1000'], where processes with
	// higher scores are preferred for being killed. If it is unset then we don't touch the current
	// value.
	// More information about kernel oom score calculation here: https://lwn.net/Articles/317814/
	OomScoreAdj *int `json:"oom_score_adj,omitempty"`

	// UidMappings is an array of User ID mappings for User Namespaces
	UidMappings []IDMap `json:"uid_mappings"`

	// GidMappings is an array of Group ID mappings for User Namespaces
	GidMappings []IDMap `json:"gid_mappings"`

	// MaskPaths specifies paths within the container's rootfs to mask over with a bind
	// mount pointing to /dev/null as to prevent reads of the file.
	MaskPaths []string `json:"mask_paths"`

	// ReadonlyPaths specifies paths within the container's rootfs to remount as read-only
	// so that these files prevent any writes.
	ReadonlyPaths []string `json:"readonly_paths"`

	// Sysctl is a map of properties and their values. It is the equivalent of using
	// sysctl -w my.property.name value in Linux.
	Sysctl map[string]string `json:"sysctl"`

	// Seccomp allows actions to be taken whenever a syscall is made within the container.
	// A number of rules are given, each having an action to be taken if a syscall matches it.
	// A default action to be taken if no rules match is also given.
	Seccomp *Seccomp `json:"seccomp"`

	// NoNewPrivileges controls whether processes in the container can gain additional privileges.
	NoNewPrivileges bool `json:"no_new_privileges,omitempty"`

	// Hooks are a collection of actions to perform at various container lifecycle events.
	// CommandHooks are serialized to JSON, but other hooks are not.
	Hooks Hooks

	// Version is the version of opencontainer specification that is supported.
	Version string `json:"version"`

	// Labels are user defined metadata that is stored in the config and populated on the state
	Labels []string `json:"labels"`

	// NoNewKeyring will not allocated a new session keyring for the container.  It will use the
	// callers keyring in this case.
	NoNewKeyring bool `json:"no_new_keyring"`

	// IntelRdt specifies settings for Intel RDT group that the container is placed into
	// to limit the resources (e.g., L3 cache, memory bandwidth) the container has available
	IntelRdt *IntelRdt `json:"intel_rdt,omitempty"`

	// RootlessEUID is set when the runc was launched with non-zero EUID.
	// Note that RootlessEUID is set to false when launched with EUID=0 in userns.
	// When RootlessEUID is set, runc creates a new userns for the container.
	// (config.json needs to contain userns settings)
	RootlessEUID bool `json:"rootless_euid,omitempty"`

	// RootlessCgroups is set when unlikely to have the full access to cgroups.
	// When RootlessCgroups is set, cgroups errors are ignored.
	RootlessCgroups bool `json:"rootless_cgroups,omitempty"`
}

// Seccomp represents syscall restrictions
// By default, only the native architecture of the kernel is allowed to be used
// for syscalls. Additional architectures can be added by specifying them in
// Architectures.
type Seccomp struct {
	DefaultAction   Action     `json:"default_action"`
	Architectures   []string   `json:"architectures"`
	Syscalls        []*Syscall `json:"syscalls"`
	DefaultErrnoRet *uint      `json:"default_errno_ret"`
}


// Action is taken upon rule match in Seccomp
type Action int

const (
	Kill Action = iota + 1
	Errno
	Trap
	Allow
	Trace
	Log
)

// Syscall is a rule to match a syscall in Seccomp
type Syscall struct {
	Name     string `json:"name"`
	Action   Action `json:"action"`
	ErrnoRet *uint  `json:"errnoRet"`
	Args     []*Arg `json:"args"`
}

// Operator is a comparison operator to be used when matching syscall arguments in Seccomp
type Operator int

const (
	EqualTo Operator = iota + 1
	NotEqualTo
	GreaterThan
	GreaterThanOrEqualTo
	LessThan
	LessThanOrEqualTo
	MaskEqualTo
)


// Arg is a rule to match a specific syscall argument in Seccomp
type Arg struct {
	Index    uint     `json:"index"`
	Value    uint64   `json:"value"`
	ValueTwo uint64   `json:"value_two"`
	Op       Operator `json:"op"`
}

// IDMap represents UID/GID Mappings for User Namespaces.
type IDMap struct {
	ContainerID int `json:"container_id"`
	HostID      int `json:"host_id"`
	Size        int `json:"size"`
}
type Hook interface {
	// Run executes the hook with the provided state.
	Run(*specs.State) error
}

// NewFunctionHook will call the provided function when the hook is run.
func NewFunctionHook(f func(*specs.State) error) FuncHook {
	return FuncHook{
		run: f,
	}
}

type FuncHook struct {
	run func(*specs.State) error
}

func (f FuncHook) Run(s *specs.State) error {
	return f.run(s)
}

type (
	HookName string
	HookList []Hook
	Hooks    map[HookName]HookList
)

type CreateOpts struct {
	CgroupName       string
	UseSystemdCgroup bool
	NoPivotRoot      bool
	NoNewKeyring     bool
	Spec             *specs.Spec
}

var namespaceMapping = map[specs.LinuxNamespaceType]NamespaceType{
	specs.PIDNamespace:     NEWPID,
	specs.NetworkNamespace: NEWNET,
	specs.MountNamespace:   NEWNS,
	specs.UserNamespace:    NEWUSER,
	specs.IPCNamespace:     NEWIPC,
	specs.UTSNamespace:     NEWUTS,
	specs.CgroupNamespace:  NEWCGROUP,
}

var mountPropagationMapping = map[string]int{
	"rprivate":    unix.MS_PRIVATE | unix.MS_REC,
	"private":     unix.MS_PRIVATE,
	"rslave":      unix.MS_SLAVE | unix.MS_REC,
	"slave":       unix.MS_SLAVE,
	"rshared":     unix.MS_SHARED | unix.MS_REC,
	"shared":      unix.MS_SHARED,
	"runbindable": unix.MS_UNBINDABLE | unix.MS_REC,
	"unbindable":  unix.MS_UNBINDABLE,
	"":            0,
}

func ConvertFromSpec(opts *CreateOpts)(config *Config, err error){
	//runcの作業ディレクトリをランタイムバンドルがあるカレントディレクトリに設定
	rcwd, err := os.Getwd()
	if err != nil {
		return
	}
	cwd, err := filepath.Abs(rcwd)
	if err != nil {
		return
	}
	spec := opts.Spec
	// configs.jsonのrootfsディレクトリを設定。
	rootfsPath := spec.Root.Path
	if !filepath.IsAbs(rootfsPath) {
		rootfsPath = filepath.Join(cwd, rootfsPath)
	}

	labels := make([]string, 0)
	for k, v := range spec.Annotations {
		labels = append(labels, k+"="+v)
	}

	config = &Config{
		Rootfs:          rootfsPath,
		NoPivotRoot:     opts.NoPivotRoot,
		Readonlyfs:      spec.Root.Readonly,
		Hostname:        spec.Hostname,
		Labels:          append(labels, "bundle="+cwd),
		NoNewKeyring:    opts.NoNewKeyring,
	}
	// configs.jsonのmountsフィールドに対応する、仕様に従ってディレクトリをマウント。
	// /Proc、/dev、/dev/pts、/dev/shm、/dev/mqueue、/sys/、/sys/fs/cgroupなど
	for _, m := range spec.Mounts {
		cm, err := createLibcontainerMount(cwd, m)
		if err != nil {
			return nil, fmt.Errorf("invalid mount %+v: %w", m, err)
		}
		config.Mounts = append(config.Mounts, cm)
	}

	// マウント・パーティション、デフォルト・マウント・パーティション AllowedDevices、OCI準拠パーティションの作成
	// AllowedDevices https://github.com/opencontainers/runc/blob/master/libcontainer/specconv/spec_linux.go
	defaultDevs, err := createDevices(spec, config)
	if err != nil {
		return nil, err
	}

	// cgroupの構成を作成
	c, err := createCgroupConfig(opts, defaultDevs)
	if err != nil {
		return nil, err
	}

	config.Cgroups = c

	if spec.Linux != nil {
		var exists bool
		if config.RootPropagation, exists = mountPropagationMapping[spec.Linux.RootfsPropagation]; !exists{
			return nil, fmt.Errorf("rootfsPropagation=%v is not supported", spec.Linux.RootfsPropagation)
		}
		if config.NoPivotRoot && (config.RootPropagation&unix.MS_PRIVATE != 0){
			return nil, xerrors.New("rootfsPropagation of [r]private is not safe without pivot_root")
		}

		for _, ns := range spec.Linux.Namespaces {
			t, exists := namespaceMapping[ns.Type]
			if !exists {
				return nil, fmt.Errorf("namespace %q does not exist", ns)
			}
			if config.Namespaces.Contains(t) {
				return nil, fmt.Errorf("malformed spec file: duplicated ns %q", ns)
			}
			config.Namespaces.Add(t, ns.Path)
		}
		if config.Namespaces.Contains(NEWNET) && config.Namespaces.PathOf(NEWNET) == "" {
			config.Networks = []*Network{
				{
					Type: "loopback",
				},
			}
		}
		if config.Namespaces.Contains(NEWUSER) {
			if err := setupUserNamespace(spec, config); err != nil {
				return nil, err
			}
		}
		config.MaskPaths = spec.Linux.MaskedPaths
		config.ReadonlyPaths = spec.Linux.ReadonlyPaths
		config.MountLabel = spec.Linux.MountLabel
		config.Sysctl = spec.Linux.Sysctl
		if spec.Linux.Seccomp != nil {
			seccomp, err := SetupSeccomp(spec.Linux.Seccomp)
			if err != nil {
				return nil, err
			}
			config.Seccomp = seccomp
		}
		if spec.Linux.IntelRdt != nil {
			config.IntelRdt = &IntelRdt{
				L3CacheSchema: spec.Linux.IntelRdt.L3CacheSchema,
				MemBwSchema:   spec.Linux.IntelRdt.MemBwSchema,
			}
		}
	}

	if spec.Process != nil {
		// OOM killerがプロセスを殺す優先度に関わる oomscoreを設定する
		config.OomScoreAdj = spec.Process.OOMScoreAdj
		// privileges
		config.NoNewPrivileges = spec.Process.NoNewPrivileges
		// umask(777とか440とかのやつ)
		config.Umask = spec.Process.User.Umask
		// selinuxのlabel
		config.ProcessLabel = spec.Process.SelinuxLabel
		// コンテナに一部の特権を付与
		if spec.Process.Capabilities != nil {
			config.Capabilities = &Capabilities{
				Bounding:    spec.Process.Capabilities.Bounding,
				Effective:   spec.Process.Capabilities.Effective,
				Permitted:   spec.Process.Capabilities.Permitted,
				Inheritable: spec.Process.Capabilities.Inheritable,
				Ambient:     spec.Process.Capabilities.Ambient,
			}
		}
	}



	createHooks(spec, config)

	config.Version = specs.Version
	return
}

func createLibcontainerMount(cwd string, m specs.Mount) (*Mount, error){
	flags, pgflags, data, ext := parseMountOptions(m.Options)
	source := m.Source
	device := m.Type
	if flags&unix.MS_BIND !=0{
		device = "bind"
		if !filepath.IsAbs(source){
			source = filepath.Join(cwd, m.Source)
		}
	}

	return &Mount{
		Device:           device,
		Source:           source,
		Destination:      m.Destination,
		Data:             data,
		Flags:            flags,
		PropagationFlags: pgflags,
		Extensions:       ext,
	}, nil
}

// parseMountOptions parses the string and returns the flags, propagation
// flags and any mount data that it contains.
func parseMountOptions(options []string) (int, []int, string, int) {
	var (
		flag     int
		pgflag   []int
		data     []string
		extFlags int
	)
	flags := map[string]struct {
		clear bool
		flag  int
	}{
		"acl":           {false, unix.MS_POSIXACL},
		"async":         {true, unix.MS_SYNCHRONOUS},
		"atime":         {true, unix.MS_NOATIME},
		"bind":          {false, unix.MS_BIND},
		"defaults":      {false, 0},
		"dev":           {true, unix.MS_NODEV},
		"diratime":      {true, unix.MS_NODIRATIME},
		"dirsync":       {false, unix.MS_DIRSYNC},
		"exec":          {true, unix.MS_NOEXEC},
		"iversion":      {false, unix.MS_I_VERSION},
		"lazytime":      {false, unix.MS_LAZYTIME},
		"loud":          {true, unix.MS_SILENT},
		"mand":          {false, unix.MS_MANDLOCK},
		"noacl":         {true, unix.MS_POSIXACL},
		"noatime":       {false, unix.MS_NOATIME},
		"nodev":         {false, unix.MS_NODEV},
		"nodiratime":    {false, unix.MS_NODIRATIME},
		"noexec":        {false, unix.MS_NOEXEC},
		"noiversion":    {true, unix.MS_I_VERSION},
		"nolazytime":    {true, unix.MS_LAZYTIME},
		"nomand":        {true, unix.MS_MANDLOCK},
		"norelatime":    {true, unix.MS_RELATIME},
		"nostrictatime": {true, unix.MS_STRICTATIME},
		"nosuid":        {false, unix.MS_NOSUID},
		"rbind":         {false, unix.MS_BIND | unix.MS_REC},
		"relatime":      {false, unix.MS_RELATIME},
		"remount":       {false, unix.MS_REMOUNT},
		"ro":            {false, unix.MS_RDONLY},
		"rw":            {true, unix.MS_RDONLY},
		"silent":        {false, unix.MS_SILENT},
		"strictatime":   {false, unix.MS_STRICTATIME},
		"suid":          {true, unix.MS_NOSUID},
		"sync":          {false, unix.MS_SYNCHRONOUS},
	}
	propagationFlags := map[string]int{
		"private":     unix.MS_PRIVATE,
		"shared":      unix.MS_SHARED,
		"slave":       unix.MS_SLAVE,
		"unbindable":  unix.MS_UNBINDABLE,
		"rprivate":    unix.MS_PRIVATE | unix.MS_REC,
		"rshared":     unix.MS_SHARED | unix.MS_REC,
		"rslave":      unix.MS_SLAVE | unix.MS_REC,
		"runbindable": unix.MS_UNBINDABLE | unix.MS_REC,
	}
	extensionFlags := map[string]struct {
		clear bool
		flag  int
	}{
		"tmpcopyup": {false, EXT_COPYUP},
	}
	for _, o := range options {
		// If the option does not exist in the flags table or the flag
		// is not supported on the platform,
		// then it is a data value for a specific fs type
		if f, exists := flags[o]; exists && f.flag != 0 {
			if f.clear {
				flag &= ^f.flag
			} else {
				flag |= f.flag
			}
		} else if f, exists := propagationFlags[o]; exists && f != 0 {
			pgflag = append(pgflag, f)
		} else if f, exists := extensionFlags[o]; exists && f.flag != 0 {
			if f.clear {
				extFlags &= ^f.flag
			} else {
				extFlags |= f.flag
			}
		} else {
			data = append(data, o)
		}
	}
	return flag, pgflag, strings.Join(data, ","), extFlags
}

func createDevices(spec *specs.Spec, config *Config) ([]*devices.Device, error) {
	// If a spec device is redundant with a default device, remove that default
	// device (the spec one takes priority).
	dedupedAllowDevs := []*devices.Device{}

next:
	for _, ad := range devices.AllowedDevices {
		if ad.Path != "" {
			for _, sd := range spec.Linux.Devices {
				if sd.Path == ad.Path {
					continue next
				}
			}
		}
		dedupedAllowDevs = append(dedupedAllowDevs, ad)
		if ad.Path != "" {
			config.Devices = append(config.Devices, ad)
		}
	}

	// Merge in additional devices from the spec.
	if spec.Linux != nil {
		for _, d := range spec.Linux.Devices {
			var uid, gid uint32
			var filemode os.FileMode = 0o666

			if d.UID != nil {
				uid = *d.UID
			}
			if d.GID != nil {
				gid = *d.GID
			}
			dt, err := stringToDeviceRune(d.Type)
			if err != nil {
				return nil, err
			}
			if d.FileMode != nil {
				filemode = *d.FileMode &^ unix.S_IFMT
			}
			device := &devices.Device{
				Rule: devices.Rule{
					Type:  dt,
					Major: d.Major,
					Minor: d.Minor,
				},
				Path:     d.Path,
				FileMode: filemode,
				Uid:      uid,
				Gid:      gid,
			}
			config.Devices = append(config.Devices, device)
		}
	}

	return dedupedAllowDevs, nil
}

func stringToDeviceRune(s string) (devices.Type, error) {
	switch s {
	case "p":
		return devices.FifoDevice, nil
	case "u", "c":
		return devices.CharDevice, nil
	case "b":
		return devices.BlockDevice, nil
	default:
		return 0, fmt.Errorf("invalid device type %q", s)
	}
}


func createCgroupConfig(opts *CreateOpts, defaultDevs []*devices.Device) (*Cgroup, error) {
	var (
		myCgroupPath string

		spec             = opts.Spec
		useSystemdCgroup = opts.UseSystemdCgroup
		name             = opts.CgroupName
	)

	c := &Cgroup{
		Resources: &Resources{},
	}

	if useSystemdCgroup {
		sp, err := initSystemdProps(spec)
		if err != nil {
			return nil, err
		}
		c.SystemdProps = sp
	}

	if spec.Linux != nil && spec.Linux.CgroupsPath != "" {
		if useSystemdCgroup {
			myCgroupPath = spec.Linux.CgroupsPath
		} else {
			myCgroupPath = cleanPath(spec.Linux.CgroupsPath)
		}
	}

	if useSystemdCgroup {
		if myCgroupPath == "" {
			// Default for c.Parent is set by systemd cgroup drivers.
			c.ScopePrefix = "runc"
			c.Name = name
		} else {
			// Parse the path from expected "slice:prefix:name"
			// for e.g. "system.slice:docker:1234"
			parts := strings.Split(myCgroupPath, ":")
			if len(parts) != 3 {
				return nil, fmt.Errorf("expected cgroupsPath to be of format \"slice:prefix:name\" for systemd cgroups, got %q instead", myCgroupPath)
			}
			c.Parent = parts[0]
			c.ScopePrefix = parts[1]
			c.Name = parts[2]
		}
	} else {
		if myCgroupPath == "" {
			c.Name = name
		}
		c.Path = myCgroupPath
	}

	// In rootless containers, any attempt to make cgroup changes is likely to fail.
	// libcontainer will validate this but ignores the error.
	if spec.Linux != nil {
		r := spec.Linux.Resources
		if r != nil {
			for i, d := range spec.Linux.Resources.Devices {
				var (
					t     = "a"
					major = int64(-1)
					minor = int64(-1)
				)
				if d.Type != "" {
					t = d.Type
				}
				if d.Major != nil {
					major = *d.Major
				}
				if d.Minor != nil {
					minor = *d.Minor
				}
				if d.Access == "" {
					return nil, fmt.Errorf("device access at %d field cannot be empty", i)
				}
				dt, err := stringToCgroupDeviceRune(t)
				if err != nil {
					return nil, err
				}
				c.Resources.Devices = append(c.Resources.Devices, &devices.Rule{
					Type:        dt,
					Major:       major,
					Minor:       minor,
					Permissions: devices.Permissions(d.Access),
					Allow:       d.Allow,
				})
			}
			if r.Memory != nil {
				if r.Memory.Limit != nil {
					c.Resources.Memory = *r.Memory.Limit
				}
				if r.Memory.Reservation != nil {
					c.Resources.MemoryReservation = *r.Memory.Reservation
				}
				if r.Memory.Swap != nil {
					c.Resources.MemorySwap = *r.Memory.Swap
				}
				if r.Memory.Swappiness != nil {
					c.Resources.MemorySwappiness = r.Memory.Swappiness
				}
				if r.Memory.DisableOOMKiller != nil {
					c.Resources.OomKillDisable = *r.Memory.DisableOOMKiller
				}
			}
			if r.CPU != nil {
				if r.CPU.Shares != nil {
					c.Resources.CpuShares = *r.CPU.Shares

					// CpuWeight is used for cgroupv2 and should be converted
					c.Resources.CpuWeight = convertCPUSharesToCgroupV2Value(c.Resources.CpuShares)
				}
				if r.CPU.Quota != nil {
					c.Resources.CpuQuota = *r.CPU.Quota
				}
				if r.CPU.Period != nil {
					c.Resources.CpuPeriod = *r.CPU.Period
				}
				if r.CPU.RealtimeRuntime != nil {
					c.Resources.CpuRtRuntime = *r.CPU.RealtimeRuntime
				}
				if r.CPU.RealtimePeriod != nil {
					c.Resources.CpuRtPeriod = *r.CPU.RealtimePeriod
				}
				c.Resources.CpusetCpus = r.CPU.Cpus
				c.Resources.CpusetMems = r.CPU.Mems
			}
			if r.Pids != nil {
				c.Resources.PidsLimit = r.Pids.Limit
			}
			if r.BlockIO != nil {
				if r.BlockIO.Weight != nil {
					c.Resources.BlkioWeight = *r.BlockIO.Weight
				}
				if r.BlockIO.LeafWeight != nil {
					c.Resources.BlkioLeafWeight = *r.BlockIO.LeafWeight
				}
				if r.BlockIO.WeightDevice != nil {
					for _, wd := range r.BlockIO.WeightDevice {
						var weight, leafWeight uint16
						if wd.Weight != nil {
							weight = *wd.Weight
						}
						if wd.LeafWeight != nil {
							leafWeight = *wd.LeafWeight
						}
						weightDevice := devices.NewWeightDevice(wd.Major, wd.Minor, weight, leafWeight)
						c.Resources.BlkioWeightDevice = append(c.Resources.BlkioWeightDevice, weightDevice)
					}
				}
				if r.BlockIO.ThrottleReadBpsDevice != nil {
					for _, td := range r.BlockIO.ThrottleReadBpsDevice {
						rate := td.Rate
						throttleDevice := devices.NewThrottleDevice(td.Major, td.Minor, rate)
						c.Resources.BlkioThrottleReadBpsDevice = append(c.Resources.BlkioThrottleReadBpsDevice, throttleDevice)
					}
				}
				if r.BlockIO.ThrottleWriteBpsDevice != nil {
					for _, td := range r.BlockIO.ThrottleWriteBpsDevice {
						rate := td.Rate
						throttleDevice := devices.NewThrottleDevice(td.Major, td.Minor, rate)
						c.Resources.BlkioThrottleWriteBpsDevice = append(c.Resources.BlkioThrottleWriteBpsDevice, throttleDevice)
					}
				}
				if r.BlockIO.ThrottleReadIOPSDevice != nil {
					for _, td := range r.BlockIO.ThrottleReadIOPSDevice {
						rate := td.Rate
						throttleDevice := devices.NewThrottleDevice(td.Major, td.Minor, rate)
						c.Resources.BlkioThrottleReadIOPSDevice = append(c.Resources.BlkioThrottleReadIOPSDevice, throttleDevice)
					}
				}
				if r.BlockIO.ThrottleWriteIOPSDevice != nil {
					for _, td := range r.BlockIO.ThrottleWriteIOPSDevice {
						rate := td.Rate
						throttleDevice := devices.NewThrottleDevice(td.Major, td.Minor, rate)
						c.Resources.BlkioThrottleWriteIOPSDevice = append(c.Resources.BlkioThrottleWriteIOPSDevice, throttleDevice)
					}
				}
			}
			for _, l := range r.HugepageLimits {
				c.Resources.HugetlbLimit = append(c.Resources.HugetlbLimit, &HugepageLimit{
					Pagesize: l.Pagesize,
					Limit:    l.Limit,
				})
			}
			if r.Network != nil {
				if r.Network.ClassID != nil {
					c.Resources.NetClsClassid = *r.Network.ClassID
				}
				for _, m := range r.Network.Priorities {
					c.Resources.NetPrioIfpriomap = append(c.Resources.NetPrioIfpriomap, &IfPrioMap{
						Interface: m.Name,
						Priority:  int64(m.Priority),
					})
				}
			}
			if len(r.Unified) > 0 {
				// copy the map
				c.Resources.Unified = make(map[string]string, len(r.Unified))
				for k, v := range r.Unified {
					c.Resources.Unified[k] = v
				}
			}
		}
	}

	// Append the default allowed devices to the end of the list.
	for _, device := range defaultDevs {
		c.Resources.Devices = append(c.Resources.Devices, &device.Rule)
	}
	return c, nil
}

// Some systemd properties are documented as having "Sec" suffix
// (e.g. TimeoutStopSec) but are expected to have "USec" suffix
// here, so let's provide conversion to improve compatibility.
func convertSecToUSec(value dbus.Variant) (dbus.Variant, error) {
	var sec uint64
	const M = 1000000
	vi := value.Value()
	switch value.Signature().String() {
	case "y":
		sec = uint64(vi.(byte)) * M
	case "n":
		sec = uint64(vi.(int16)) * M
	case "q":
		sec = uint64(vi.(uint16)) * M
	case "i":
		sec = uint64(vi.(int32)) * M
	case "u":
		sec = uint64(vi.(uint32)) * M
	case "x":
		sec = uint64(vi.(int64)) * M
	case "t":
		sec = vi.(uint64) * M
	case "d":
		sec = uint64(vi.(float64) * M)
	default:
		return value, errors.New("not a number")
	}
	return dbus.MakeVariant(sec), nil
}

// systemd property name check: latin letters only, at least 3 of them
var isValidName = regexp.MustCompile(`^[a-zA-Z]{3,}$`).MatchString

var isSecSuffix = regexp.MustCompile(`[a-z]Sec$`).MatchString

func initSystemdProps(spec *specs.Spec) ([]systemdDbus.Property, error) {
	const keyPrefix = "org.systemd.property."
	var sp []systemdDbus.Property

	for k, v := range spec.Annotations {
		name := strings.TrimPrefix(k, keyPrefix)
		if len(name) == len(k) { // prefix not there
			continue
		}
		if !isValidName(name) {
			return nil, fmt.Errorf("Annotation %s name incorrect: %s", k, name)
		}
		value, err := dbus.ParseVariant(v, dbus.Signature{})
		if err != nil {
			return nil, fmt.Errorf("Annotation %s=%s value parse error: %w", k, v, err)
		}
		if isSecSuffix(name) {
			name = strings.TrimSuffix(name, "Sec") + "USec"
			value, err = convertSecToUSec(value)
			if err != nil {
				return nil, fmt.Errorf("Annotation %s=%s value parse error: %w", k, v, err)
			}
		}
		sp = append(sp, systemdDbus.Property{Name: name, Value: value})
	}

	return sp, nil
}


// CleanPath makes a path safe for use with filepath.Join. This is done by not
// only cleaning the path, but also (if the path is relative) adding a leading
// '/' and cleaning it (then removing the leading '/'). This ensures that a
// path resulting from prepending another path will always resolve to lexically
// be a subdirectory of the prefixed path. This is all done lexically, so paths
// that include symlinks won't be safe as a result of using CleanPath.
func cleanPath(path string) string {
	// Deal with empty strings nicely.
	if path == "" {
		return ""
	}

	// Ensure that all paths are cleaned (especially problematic ones like
	// "/../../../../../" which can cause lots of issues).
	path = filepath.Clean(path)

	// If the path isn't absolute, we need to do more processing to fix paths
	// such as "../../../../<etc>/some/path". We also shouldn't convert absolute
	// paths to relative ones.
	if !filepath.IsAbs(path) {
		path = filepath.Clean(string(os.PathSeparator) + path)
		// This can't fail, as (by definition) all paths are relative to root.
		path, _ = filepath.Rel(string(os.PathSeparator), path)
	}

	// Clean the path again for good measure.
	return filepath.Clean(path)
}

func stringToCgroupDeviceRune(s string) (devices.Type, error) {
	switch s {
	case "a":
		return devices.WildcardDevice, nil
	case "b":
		return devices.BlockDevice, nil
	case "c":
		return devices.CharDevice, nil
	default:
		return 0, fmt.Errorf("invalid cgroup device type %q", s)
	}
}


// Since the OCI spec is designed for cgroup v1, in some cases
// there is need to convert from the cgroup v1 configuration to cgroup v2
// the formula for cpuShares is y = (1 + ((x - 2) * 9999) / 262142)
// convert from [2-262144] to [1-10000]
// 262144 comes from Linux kernel definition "#define MAX_SHARES (1UL << 18)"
func convertCPUSharesToCgroupV2Value(cpuShares uint64) uint64 {
	if cpuShares == 0 {
		return 0
	}
	return (1 + ((cpuShares-2)*9999)/262142)
}


func setupUserNamespace(spec *specs.Spec, config *Config) error {
	create := func(m specs.LinuxIDMapping) IDMap {
		return IDMap{
			HostID:      int(m.HostID),
			ContainerID: int(m.ContainerID),
			Size:        int(m.Size),
		}
	}
	if spec.Linux != nil {
		for _, m := range spec.Linux.UIDMappings {
			config.UidMappings = append(config.UidMappings, create(m))
		}
		for _, m := range spec.Linux.GIDMappings {
			config.GidMappings = append(config.GidMappings, create(m))
		}
	}
	rootUID, err := config.HostRootUID()
	if err != nil {
		return err
	}
	rootGID, err := config.HostRootGID()
	if err != nil {
		return err
	}
	for _, node := range config.Devices {
		node.Uid = uint32(rootUID)
		node.Gid = uint32(rootGID)
	}
	return nil
}


func SetupSeccomp(config *specs.LinuxSeccomp) (*Seccomp, error) {
	if config == nil {
		return nil, nil
	}

	// No default action specified, no syscalls listed, assume seccomp disabled
	if config.DefaultAction == "" && len(config.Syscalls) == 0 {
		return nil, nil
	}

	// We don't currently support seccomp flags.
	if len(config.Flags) != 0 {
		return nil, errors.New("seccomp flags are not yet supported by runc")
	}

	newConfig := new(Seccomp)
	newConfig.Syscalls = []*Syscall{}

	if len(config.Architectures) > 0 {
		newConfig.Architectures = []string{}
		for _, arch := range config.Architectures {
			newArch, err := seccomp.ConvertStringToArch(string(arch))
			if err != nil {
				return nil, err
			}
			newConfig.Architectures = append(newConfig.Architectures, newArch)
		}
	}

	// Convert default action from string representation
	newDefaultAction, err := seccomp.ConvertStringToAction(string(config.DefaultAction))
	if err != nil {
		return nil, err
	}
	newConfig.DefaultAction = newDefaultAction
	newConfig.DefaultErrnoRet = config.DefaultErrnoRet

	// Loop through all syscall blocks and convert them to libcontainer format
	for _, call := range config.Syscalls {
		newAction, err := seccomp.ConvertStringToAction(string(call.Action))
		if err != nil {
			return nil, err
		}

		for _, name := range call.Names {
			newCall := Syscall{
				Name:     name,
				Action:   newAction,
				ErrnoRet: call.ErrnoRet,
				Args:     []*Arg{},
			}
			// Loop through all the arguments of the syscall and convert them
			for _, arg := range call.Args {
				newOp, err := seccomp.ConvertStringToOperator(string(arg.Op))
				if err != nil {
					return nil, err
				}

				newArg := Arg{
					Index:    arg.Index,
					Value:    arg.Value,
					ValueTwo: arg.ValueTwo,
					Op:       newOp,
				}

				newCall.Args = append(newCall.Args, &newArg)
			}
			newConfig.Syscalls = append(newConfig.Syscalls, &newCall)
		}
	}

	return newConfig, nil
}


func createHooks(rspec *specs.Spec, config *Config) {
	config.Hooks = Hooks{}
	if rspec.Hooks != nil {
		for _, h := range rspec.Hooks.Prestart {
			cmd := createCommandHook(h)
			config.Hooks[Prestart] = append(config.Hooks[Prestart], NewCommandHook(cmd))
		}
		for _, h := range rspec.Hooks.CreateRuntime {
			cmd := createCommandHook(h)
			config.Hooks[CreateRuntime] = append(config.Hooks[CreateRuntime], NewCommandHook(cmd))
		}
		for _, h := range rspec.Hooks.CreateContainer {
			cmd := createCommandHook(h)
			config.Hooks[CreateContainer] = append(config.Hooks[CreateContainer], NewCommandHook(cmd))
		}
		for _, h := range rspec.Hooks.StartContainer {
			cmd := createCommandHook(h)
			config.Hooks[StartContainer] = append(config.Hooks[StartContainer], NewCommandHook(cmd))
		}
		for _, h := range rspec.Hooks.Poststart {
			cmd := createCommandHook(h)
			config.Hooks[Poststart] = append(config.Hooks[Poststart], NewCommandHook(cmd))
		}
		for _, h := range rspec.Hooks.Poststop {
			cmd := createCommandHook(h)
			config.Hooks[Poststop] = append(config.Hooks[Poststop], NewCommandHook(cmd))
		}
	}
}

func createCommandHook(h specs.Hook) Command {
	cmd := Command{
		Path: h.Path,
		Args: h.Args,
		Env:  h.Env,
	}
	if h.Timeout != nil {
		d := time.Duration(*h.Timeout) * time.Second
		cmd.Timeout = &d
	}
	return cmd
}
