package parsers

import "github.com/ethanolivertroy/kev-checker/internal/models"

// Parser is the interface for dependency file parsers
type Parser interface {
	// CanParse returns true if this parser can handle the given filename
	CanParse(filename string) bool

	// Parse extracts dependencies from the file content
	Parse(filepath string, content []byte) ([]models.Dependency, error)
}

// GetAllParsers returns all available parsers
func GetAllParsers() []Parser {
	return []Parser{
		&PythonRequirementsParser{},
		&PythonPyProjectParser{},
		&NodePackageLockParser{},
		&NodePackageJSONParser{},
		&GoModParser{},
	}
}
