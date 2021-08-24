package spec

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/xerrors"
)

const configPath = "config.json"

func LoadSpec(path string) (*specs.Spec, error) {
	filepath := filepath.Join(path, configPath)
	file, err := os.Open(filepath)
	if err != nil {
		return nil, xerrors.Errorf("failed to open config.json: %w", err)
	}

	var spec *specs.Spec
	if err := json.NewDecoder(file).Decode(&spec); err != nil {
		return nil, xerrors.Errorf("failed to decode config.json: %w", err)
	}
	return spec, nil
}
