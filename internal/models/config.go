package models

import "time"

// Config holds configuration for the scanner
type Config struct {
	// Paths to scan for dependency files
	Paths []string

	// Output settings
	OutputFormat string // "terminal", "json", "sarif"
	OutputFile   string // Optional output file path

	// Behavior settings
	FailOnKEV     bool    // Exit with code 1 if KEVs found
	EPSSThreshold float64 // Only report if EPSS >= threshold (0-1)

	// Cache settings
	CacheTTL time.Duration
	NoCache  bool

	// API settings
	Timeout       time.Duration
	MaxConcurrent int
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Paths:         []string{"."},
		OutputFormat:  "terminal",
		FailOnKEV:     true,
		EPSSThreshold: 0,
		CacheTTL:      24 * time.Hour,
		NoCache:       false,
		Timeout:       60 * time.Second,
		MaxConcurrent: 10,
	}
}
