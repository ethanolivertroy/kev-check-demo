package parsers

import (
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/ethanolivertroy/kev-check-demo/internal/models"
)

// PythonRequirementsParser parses requirements.txt files
type PythonRequirementsParser struct{}

// CanParse returns true for requirements.txt files
func (p *PythonRequirementsParser) CanParse(filename string) bool {
	return filename == "requirements.txt" ||
		strings.HasSuffix(filename, "-requirements.txt") ||
		strings.HasSuffix(filename, "_requirements.txt") ||
		filename == "requirements-dev.txt" ||
		filename == "requirements-test.txt"
}

// versionPattern matches package version specifiers like ==1.2.3, >=1.2.3, ~=1.2.3
var versionPattern = regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*([<>=!~]+)\s*([\d.]+.*)$`)

// simplePattern matches just package names without versions
var simplePattern = regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*$`)

// Parse extracts dependencies from requirements.txt content
func (p *PythonRequirementsParser) Parse(filepath string, content []byte) ([]models.Dependency, error) {
	var deps []models.Dependency
	lines := strings.Split(string(content), "\n")

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines, comments, and options
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Remove inline comments
		if idx := strings.Index(line, "#"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Remove extras like [security]
		if idx := strings.Index(line, "["); idx > 0 {
			bracketEnd := strings.Index(line, "]")
			if bracketEnd > idx {
				line = line[:idx] + line[bracketEnd+1:]
				line = strings.TrimSpace(line)
			}
		}

		name, version := parseVersionSpec(line)
		if name != "" {
			deps = append(deps, models.Dependency{
				Name:       strings.ToLower(name), // PyPI is case-insensitive
				Version:    version,
				Ecosystem:  models.EcosystemPyPI,
				SourceFile: filepath,
				Line:       lineNum + 1,
			})
		}
	}

	return deps, nil
}

func parseVersionSpec(line string) (name string, version string) {
	// Try exact/pinned version patterns
	if matches := versionPattern.FindStringSubmatch(line); matches != nil {
		name = matches[1]
		version = matches[3]
		return
	}

	// Try simple package name (no version)
	if matches := simplePattern.FindStringSubmatch(line); matches != nil {
		name = matches[1]
		version = ""
		return
	}

	return "", ""
}

// PythonPyProjectParser parses pyproject.toml files
type PythonPyProjectParser struct{}

// CanParse returns true for pyproject.toml files
func (p *PythonPyProjectParser) CanParse(filename string) bool {
	return filename == "pyproject.toml"
}

// pyproject represents the structure of pyproject.toml
type pyproject struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	Tool struct {
		Poetry struct {
			Dependencies    map[string]interface{} `toml:"dependencies"`
			DevDependencies map[string]interface{} `toml:"dev-dependencies"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

// Parse extracts dependencies from pyproject.toml content
func (p *PythonPyProjectParser) Parse(filepath string, content []byte) ([]models.Dependency, error) {
	var proj pyproject
	if err := toml.Unmarshal(content, &proj); err != nil {
		return nil, err
	}

	var deps []models.Dependency

	// Parse PEP 621 dependencies (project.dependencies)
	for _, dep := range proj.Project.Dependencies {
		name, version := parsePEP508(dep)
		if name != "" {
			deps = append(deps, models.Dependency{
				Name:       strings.ToLower(name),
				Version:    version,
				Ecosystem:  models.EcosystemPyPI,
				SourceFile: filepath,
			})
		}
	}

	// Parse Poetry dependencies
	for name, val := range proj.Tool.Poetry.Dependencies {
		if name == "python" {
			continue
		}
		version := extractPoetryVersion(val)
		deps = append(deps, models.Dependency{
			Name:       strings.ToLower(name),
			Version:    version,
			Ecosystem:  models.EcosystemPyPI,
			SourceFile: filepath,
		})
	}

	return deps, nil
}

// parsePEP508 parses a PEP 508 dependency specification
func parsePEP508(spec string) (name string, version string) {
	// Simple parsing for common patterns
	// e.g., "requests>=2.28.0", "flask[async]>=2.0", "django==4.2"

	// Remove extras
	if idx := strings.Index(spec, "["); idx > 0 {
		bracketEnd := strings.Index(spec, "]")
		if bracketEnd > idx {
			spec = spec[:idx] + spec[bracketEnd+1:]
		}
	}

	// Remove environment markers
	if idx := strings.Index(spec, ";"); idx > 0 {
		spec = spec[:idx]
	}

	spec = strings.TrimSpace(spec)

	if matches := versionPattern.FindStringSubmatch(spec); matches != nil {
		return matches[1], matches[3]
	}

	if matches := simplePattern.FindStringSubmatch(spec); matches != nil {
		return matches[1], ""
	}

	return "", ""
}

func extractPoetryVersion(val interface{}) string {
	switch v := val.(type) {
	case string:
		// Remove ^ or ~ prefixes, keep the version
		v = strings.TrimPrefix(v, "^")
		v = strings.TrimPrefix(v, "~")
		return v
	case map[string]interface{}:
		if ver, ok := v["version"].(string); ok {
			ver = strings.TrimPrefix(ver, "^")
			ver = strings.TrimPrefix(ver, "~")
			return ver
		}
	}
	return ""
}
