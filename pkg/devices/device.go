package devices

import "os"


const (
	Wildcard = -1
)



type Type rune

const (
	WildcardDevice Type = 'a'
	BlockDevice    Type = 'b'
	CharDevice     Type = 'c' // or 'u'
	FifoDevice     Type = 'p'
)

// Permissions is a cgroupv1-style string to represent device access. It
// has to be a string for backward compatibility reasons, hence why it has
// methods to do set operations.
type Permissions string

const (
	deviceRead uint = (1 << iota)
	deviceWrite
	deviceMknod
)

type Device struct {
	Rule

	// Path to the device.
	Path string `json:"path"`

	// FileMode permission bits for the device.
	FileMode os.FileMode `json:"file_mode"`

	// Uid of the device.
	Uid uint32 `json:"uid"`

	// Gid of the device.
	Gid uint32 `json:"gid"`
}

var AllowedDevices = []*Device{
	// allow mknod for any device
	{
		Rule: Rule{
			Type:        CharDevice,
			Major:       Wildcard,
			Minor:       Wildcard,
			Permissions: "m",
			Allow:       true,
		},
	},
	{
		Rule: Rule{
			Type:        BlockDevice,
			Major:       Wildcard,
			Minor:       Wildcard,
			Permissions: "m",
			Allow:       true,
		},
	},
	{
		Path:     "/dev/null",
		FileMode: 0o666,
		Uid:      0,
		Gid:      0,
		Rule: Rule{
			Type:        CharDevice,
			Major:       1,
			Minor:       3,
			Permissions: "rwm",
			Allow:       true,
		},
	},
	{
		Path:     "/dev/random",
		FileMode: 0o666,
		Uid:      0,
		Gid:      0,
		Rule: Rule{
			Type:        CharDevice,
			Major:       1,
			Minor:       8,
			Permissions: "rwm",
			Allow:       true,
		},
	},
	{
		Path:     "/dev/full",
		FileMode: 0o666,
		Uid:      0,
		Gid:      0,
		Rule: Rule{
			Type:        CharDevice,
			Major:       1,
			Minor:       7,
			Permissions: "rwm",
			Allow:       true,
		},
	},
	{
		Path:     "/dev/tty",
		FileMode: 0o666,
		Uid:      0,
		Gid:      0,
		Rule: Rule{
			Type:        CharDevice,
			Major:       5,
			Minor:       0,
			Permissions: "rwm",
			Allow:       true,
		},
	},
	{
		Path:     "/dev/zero",
		FileMode: 0o666,
		Uid:      0,
		Gid:      0,
		Rule: Rule{
			Type:        CharDevice,
			Major:       1,
			Minor:       5,
			Permissions: "rwm",
			Allow:       true,
		},
	},
	{
		Path:     "/dev/urandom",
		FileMode: 0o666,
		Uid:      0,
		Gid:      0,
		Rule: Rule{
			Type:        CharDevice,
			Major:       1,
			Minor:       9,
			Permissions: "rwm",
			Allow:       true,
		},
	},
	// /dev/pts/ - pts namespaces are "coming soon"
	{
		Rule: Rule{
			Type:        CharDevice,
			Major:       136,
			Minor:       Wildcard,
			Permissions: "rwm",
			Allow:       true,
		},
	},
	{
		Rule: Rule{
			Type:        CharDevice,
			Major:       5,
			Minor:       2,
			Permissions: "rwm",
			Allow:       true,
		},
	},
	// tuntap
	{
		Rule: Rule{
			Type:        CharDevice,
			Major:       10,
			Minor:       200,
			Permissions: "rwm",
			Allow:       true,
		},
	},
}



type Rule struct {
	// Type of device ('c' for char, 'b' for block). If set to 'a', this rule
	// acts as a wildcard and all fields other than Allow are ignored.
	Type Type `json:"type"`

	// Major is the device's major number.
	Major int64 `json:"major"`

	// Minor is the device's minor number.
	Minor int64 `json:"minor"`

	// Permissions is the set of permissions that this rule applies to (in the
	// cgroupv1 format -- any combination of "rwm").
	Permissions Permissions `json:"permissions"`

	// Allow specifies whether this rule is allowed.
	Allow bool `json:"allow"`
}


// blockIODevice holds major:minor format supported in blkio cgroup
type blockIODevice struct {
	// Major is the device's major number
	Major int64 `json:"major"`
	// Minor is the device's minor number
	Minor int64 `json:"minor"`
}

// WeightDevice struct holds a `major:minor weight`|`major:minor leaf_weight` pair
type WeightDevice struct {
	blockIODevice
	// Weight is the bandwidth rate for the device, range is from 10 to 1000
	Weight uint16 `json:"weight"`
	// LeafWeight is the bandwidth rate for the device while competing with the cgroup's child cgroups, range is from 10 to 1000, cfq scheduler only
	LeafWeight uint16 `json:"leafWeight"`
}

// NewWeightDevice returns a configured WeightDevice pointer
func NewWeightDevice(major, minor int64, weight, leafWeight uint16) *WeightDevice {
	wd := &WeightDevice{}
	wd.Major = major
	wd.Minor = minor
	wd.Weight = weight
	wd.LeafWeight = leafWeight
	return wd
}

// ThrottleDevice struct holds a `major:minor rate_per_second` pair
type ThrottleDevice struct {
	blockIODevice
	// Rate is the IO rate limit per cgroup per device
	Rate uint64 `json:"rate"`
}

// NewThrottleDevice returns a configured ThrottleDevice pointer
func NewThrottleDevice(major, minor int64, rate uint64) *ThrottleDevice {
	td := &ThrottleDevice{}
	td.Major = major
	td.Minor = minor
	td.Rate = rate
	return td
}
