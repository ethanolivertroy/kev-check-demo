package parsers

import (
	"strings"

	"github.com/ethanolivertroy/kev-check-demo/internal/models"
	"golang.org/x/mod/modfile"
)

// GoModParser parses go.mod files
type GoModParser struct {
	IncludeIndirect bool // Whether to include indirect dependencies
}

// CanParse returns true for go.mod files
func (p *GoModParser) CanParse(filename string) bool {
	return filename == "go.mod"
}

// Parse extracts dependencies from go.mod content
func (p *GoModParser) Parse(filepath string, content []byte) ([]models.Dependency, error) {
	mod, err := modfile.Parse(filepath, content, nil)
	if err != nil {
		return nil, err
	}

	var deps []models.Dependency

	for _, req := range mod.Require {
		// Skip indirect deps unless explicitly requested
		if req.Indirect && !p.IncludeIndirect {
			continue
		}

		// Clean up version (remove v prefix for OSV)
		version := req.Mod.Version
		version = strings.TrimPrefix(version, "v")

		deps = append(deps, models.Dependency{
			Name:       req.Mod.Path,
			Version:    version,
			Ecosystem:  models.EcosystemGo,
			SourceFile: filepath,
		})
	}

	return deps, nil
}
