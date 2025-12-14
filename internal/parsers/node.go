package parsers

import (
	"encoding/json"
	"strings"

	"github.com/ethanolivertroy/kev-checker/internal/models"
)

// NodePackageLockParser parses package-lock.json files
type NodePackageLockParser struct{}

// CanParse returns true for package-lock.json files
func (p *NodePackageLockParser) CanParse(filename string) bool {
	return filename == "package-lock.json"
}

// packageLock represents the structure of package-lock.json (v2/v3)
type packageLock struct {
	LockfileVersion int `json:"lockfileVersion"`
	// V2/V3 format
	Packages map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev"`
	} `json:"packages"`
	// V1 format
	Dependencies map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev"`
	} `json:"dependencies"`
}

// Parse extracts dependencies from package-lock.json content
func (p *NodePackageLockParser) Parse(filepath string, content []byte) ([]models.Dependency, error) {
	var lock packageLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, err
	}

	var deps []models.Dependency
	seen := make(map[string]bool)

	// V2/V3 format (packages map)
	for path, pkg := range lock.Packages {
		if path == "" {
			continue // Skip root package
		}

		// Extract package name from path like "node_modules/lodash" or "node_modules/@types/node"
		name := path
		if strings.HasPrefix(path, "node_modules/") {
			name = strings.TrimPrefix(path, "node_modules/")
			// Handle nested node_modules
			if idx := strings.LastIndex(name, "node_modules/"); idx >= 0 {
				name = name[idx+len("node_modules/"):]
			}
		}

		if name == "" || seen[name+"@"+pkg.Version] {
			continue
		}
		seen[name+"@"+pkg.Version] = true

		deps = append(deps, models.Dependency{
			Name:       name,
			Version:    pkg.Version,
			Ecosystem:  models.EcosystemNpm,
			SourceFile: filepath,
		})
	}

	// V1 format fallback (if no packages found)
	if len(deps) == 0 {
		for name, pkg := range lock.Dependencies {
			deps = append(deps, models.Dependency{
				Name:       name,
				Version:    pkg.Version,
				Ecosystem:  models.EcosystemNpm,
				SourceFile: filepath,
			})
		}
	}

	return deps, nil
}

// NodePackageJSONParser parses package.json files (direct dependencies only)
type NodePackageJSONParser struct{}

// CanParse returns true for package.json files
func (p *NodePackageJSONParser) CanParse(filename string) bool {
	return filename == "package.json"
}

// packageJSON represents the structure of package.json
type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// Parse extracts dependencies from package.json content
func (p *NodePackageJSONParser) Parse(filepath string, content []byte) ([]models.Dependency, error) {
	var pkg packageJSON
	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil, err
	}

	var deps []models.Dependency

	// Add production dependencies
	for name, version := range pkg.Dependencies {
		deps = append(deps, models.Dependency{
			Name:       name,
			Version:    cleanNpmVersion(version),
			Ecosystem:  models.EcosystemNpm,
			SourceFile: filepath,
		})
	}

	// Add dev dependencies
	for name, version := range pkg.DevDependencies {
		deps = append(deps, models.Dependency{
			Name:       name,
			Version:    cleanNpmVersion(version),
			Ecosystem:  models.EcosystemNpm,
			SourceFile: filepath,
		})
	}

	return deps, nil
}

// cleanNpmVersion removes version prefixes like ^, ~, etc.
func cleanNpmVersion(version string) string {
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	version = strings.TrimPrefix(version, ">=")
	version = strings.TrimPrefix(version, ">")
	version = strings.TrimPrefix(version, "<=")
	version = strings.TrimPrefix(version, "<")
	version = strings.TrimPrefix(version, "=")
	return version
}
