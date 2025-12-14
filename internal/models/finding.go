package models

import "time"

// Finding represents a vulnerability finding for a dependency
type Finding struct {
	Dependency Dependency
	CVEs       []CVEInfo // All CVEs affecting this dependency
	KEVs       []KEVInfo // CVEs that are in the KEV catalog
}

// HasKEV returns true if this finding has any KEV vulnerabilities
func (f Finding) HasKEV() bool {
	return len(f.KEVs) > 0
}

// CVEInfo represents information about a CVE
type CVEInfo struct {
	ID      string
	Summary string
	Source  string // e.g., "OSV", "GHSA"
}

// KEVInfo represents a Known Exploited Vulnerability from CISA
type KEVInfo struct {
	CVEID             string
	VendorProject     string
	Product           string
	VulnerabilityName string
	DateAdded         time.Time
	DueDate           time.Time
	ShortDescription  string
	RequiredAction    string
	RansomwareUse     bool
	CWEs              []string
	Notes             string
	EPSSScore         float64
	EPSSPercentile    float64
}

// EPSSScore represents EPSS scoring data
type EPSSScore struct {
	Score      float64
	Percentile float64
}
