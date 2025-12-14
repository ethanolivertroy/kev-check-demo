package models

// Ecosystem represents a package ecosystem
type Ecosystem string

const (
	EcosystemPyPI Ecosystem = "PyPI"
	EcosystemNpm  Ecosystem = "npm"
	EcosystemGo   Ecosystem = "Go"
)

// Dependency represents a single package dependency
type Dependency struct {
	Name       string
	Version    string
	Ecosystem  Ecosystem
	SourceFile string // File where this dependency was found
	Line       int    // Line number in source file (if available)
}

// String returns a human-readable representation
func (d Dependency) String() string {
	return d.Name + "@" + d.Version
}
