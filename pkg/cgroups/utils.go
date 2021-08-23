package cgroups

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"sync"
)

const (
	CgroupProcesses   = "cgroup.procs"
	unifiedMountpoint = "/sys/fs/cgroup"
)


var (
	isUnifiedOnce sync.Once
	isUnified     bool
	inUserNS bool
	nsOnce   sync.Once
)


// IsCgroup2UnifiedMode returns whether we are running in cgroup v2 unified mode.
func IsCgroup2UnifiedMode() bool {
	isUnifiedOnce.Do(func() {
		var st unix.Statfs_t
		err := unix.Statfs(unifiedMountpoint, &st)
		if err != nil {
			if os.IsNotExist(err) && runningInUserNS() {

				isUnified = false
				return
			}
			panic(fmt.Sprintf("cannot statfs cgroup root: %s", err))
		}
		isUnified = st.Type == unix.CGROUP2_SUPER_MAGIC
	})
	return isUnified
}

// runningInUserNS detects whether we are currently running in a user namespace.
// Originally copied from github.com/lxc/lxd/shared/util.go
func runningInUserNS() bool {
	nsOnce.Do(func() {
		uidmap, err := user.CurrentProcessUIDMap()
		if err != nil {
			// This kernel-provided file only exists if user namespaces are supported
			return
		}
		inUserNS = uidMapInUserNS(uidmap)
	})
	return inUserNS
}