package spec

import (
	"encoding/json"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
	"os"
	"path/filepath"
)

func SetupSpec(context *cli.Context, configPath string) (spec *specs.Spec,err error){
	bundle := context.String("bundle")
	if bundle != "" {
		if err := os.Chdir(bundle); err != nil {
			return
		}
	}
	spec, err = loadSpec(configPath)
	if err != nil {
		return
	}
	return
}

func loadSpec(path string) (spec *specs.Spec, err error){
	var file *os.File
	file, err = os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, xerrors.Errorf("JSON specification file %s not found", path)
		}
		return nil, err
	}
	defer file.Close()

	if err = json.NewDecoder(file).Decode(&spec); err != nil {
		return nil, err
	}
	return spec, validateProcessSpec(spec.Process)
}

func validateProcessSpec(spec *specs.Process) (err error){
	if spec.Cwd == ""{
		err = xerrors.Errorf("spec.Cwd property must not be empty")
		return
	}
	if !filepath.IsAbs(spec.Cwd) {
		err= xerrors.Errorf("spec.Cwd mut be an absolute path")
		return
	}
	if len(spec.Args) == 0{
		err= xerrors.Errorf("args mut not be empty")
		return
	}
	return
}