package reporter

import "github.com/ethanolivertroy/kev-check-demo/internal/models"

// Reporter is the interface for output formatters
type Reporter interface {
	// Report generates output for the given findings
	Report(findings []models.Finding) ([]byte, error)
}

// Get returns a reporter for the specified format
func Get(format string) Reporter {
	switch format {
	case "json":
		return &JSONReporter{}
	case "sarif":
		return &SARIFReporter{}
	default:
		return &TerminalReporter{}
	}
}
