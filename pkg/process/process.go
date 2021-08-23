package process

import (
	"github.com/opencontainers/runtime-spec/specs-go"
)

type Process struct {

}


// newProcess returns a new libcontainer Process with the arguments from the
// spec and stdio from the current process.
// libcontainer.Processはほとんど spec.Process由来のもの
func new(p specs.Process, init bool, logLevel string) (*Process, error) {
	process := &Process{
		//Args: p.Args,
		//Env:  p.Env,
		//// TODO: fix libcontainer's API to better support uid/gid in a typesafe way.
		//User:            fmt.Sprintf("%d:%d", p.User.UID, p.User.GID),
		//Cwd:             p.Cwd,
		//Label:           p.SelinuxLabel,
		//NoNewPrivileges: &p.NoNewPrivileges,
		//AppArmorProfile: p.ApparmorProfile,
		//Init:            init,
		//LogLevel:        logLevel,
	}

	//if p.ConsoleSize != nil {
	//	lp.ConsoleWidth = uint16(p.ConsoleSize.Width)
	//	lp.ConsoleHeight = uint16(p.ConsoleSize.Height)
	//}

	//if p.Capabilities != nil {
	//	lp.Capabilities = &configs.Capabilities{}
	//	lp.Capabilities.Bounding = p.Capabilities.Bounding
	//	lp.Capabilities.Effective = p.Capabilities.Effective
	//	lp.Capabilities.Inheritable = p.Capabilities.Inheritable
	//	lp.Capabilities.Permitted = p.Capabilities.Permitted
	//	lp.Capabilities.Ambient = p.Capabilities.Ambient
	//}

	//for _, gid := range p.User.AdditionalGids {
	//	lp.AdditionalGroups = append(lp.AdditionalGroups, strconv.FormatUint(uint64(gid), 10))
	//}
	//for _, rlimit := range p.Rlimits {
	//	rl, err := createLibContainerRlimit(rlimit)
	//	if err != nil {
	//		return nil, err
	//	}
	//	lp.Rlimits = append(lp.Rlimits, rl)
	//}
	return process, nil
}

