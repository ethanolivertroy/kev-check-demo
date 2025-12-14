package reporter

import (
	"encoding/json"
	"fmt"

	"github.com/ethanolivertroy/kev-checker/internal/models"
)

// SARIFReporter outputs findings in SARIF format for GitHub Code Scanning
type SARIFReporter struct{}

// SARIF structures
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription sarifText        `json:"shortDescription"`
	FullDescription  sarifText        `json:"fullDescription"`
	Help             sarifText        `json:"help"`
	HelpURI          string           `json:"helpUri"`
	DefaultConfig    sarifRuleConfig  `json:"defaultConfiguration"`
	Properties       sarifProperties  `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifProperties struct {
	Tags           []string `json:"tags"`
	SecuritySeverity string `json:"security-severity,omitempty"`
}

type sarifResult struct {
	RuleID              string              `json:"ruleId"`
	RuleIndex           int                 `json:"ruleIndex"`
	Level               string              `json:"level"`
	Message             sarifText           `json:"message"`
	Locations           []sarifLocation     `json:"locations"`
	PartialFingerprints map[string]string   `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

// Report generates SARIF output for the given findings
func (r *SARIFReporter) Report(findings []models.Finding) ([]byte, error) {
	rules, ruleIndexMap := r.buildRules(findings)

	report := sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "kev-checker",
					Version:        "1.0.0",
					InformationURI: "https://github.com/ethanolivertroy/kev-checker",
					Rules:          rules,
				},
			},
			Results: r.buildResults(findings, ruleIndexMap),
		}},
	}

	return json.MarshalIndent(report, "", "  ")
}

func (r *SARIFReporter) buildRules(findings []models.Finding) ([]sarifRule, map[string]int) {
	ruleMap := make(map[string]sarifRule)
	ruleIndexMap := make(map[string]int)

	for _, f := range findings {
		for _, kev := range f.KEVs {
			if _, exists := ruleMap[kev.CVEID]; exists {
				continue
			}

			level := "error"
			severity := "8.0" // High severity for all KEVs
			tags := []string{"security", "vulnerability", "kev", "cisa"}

			if kev.RansomwareUse {
				severity = "9.5" // Critical for ransomware
				tags = append(tags, "ransomware")
			}

			helpText := fmt.Sprintf("Required Action: %s\n\nDue Date: %s\n\nThis vulnerability is in the CISA Known Exploited Vulnerabilities catalog.",
				kev.RequiredAction, kev.DueDate.Format("2006-01-02"))

			ruleMap[kev.CVEID] = sarifRule{
				ID:   kev.CVEID,
				Name: kev.VulnerabilityName,
				ShortDescription: sarifText{
					Text: fmt.Sprintf("KEV: %s - %s", kev.CVEID, kev.VulnerabilityName),
				},
				FullDescription: sarifText{
					Text: kev.ShortDescription,
				},
				Help: sarifText{
					Text: helpText,
				},
				HelpURI:       fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", kev.CVEID),
				DefaultConfig: sarifRuleConfig{Level: level},
				Properties: sarifProperties{
					Tags:             tags,
					SecuritySeverity: severity,
				},
			}
		}
	}

	// Convert map to slice and build index map
	rules := make([]sarifRule, 0, len(ruleMap))
	for cveID, rule := range ruleMap {
		ruleIndexMap[cveID] = len(rules)
		rules = append(rules, rule)
	}

	return rules, ruleIndexMap
}

func (r *SARIFReporter) buildResults(findings []models.Finding, ruleIndexMap map[string]int) []sarifResult {
	var results []sarifResult

	for _, f := range findings {
		for _, kev := range f.KEVs {
			msg := fmt.Sprintf("Dependency %s has known exploited vulnerability %s: %s",
				f.Dependency.String(), kev.CVEID, kev.VulnerabilityName)

			if kev.EPSSScore > 0 {
				msg += fmt.Sprintf(" (EPSS: %.1f%%)", kev.EPSSScore*100)
			}

			if kev.RansomwareUse {
				msg += " [Known ransomware usage]"
			}

			location := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifact{
						URI: f.Dependency.SourceFile,
					},
				},
			}

			if f.Dependency.Line > 0 {
				location.PhysicalLocation.Region = sarifRegion{
					StartLine: f.Dependency.Line,
				}
			}

			results = append(results, sarifResult{
				RuleID:    kev.CVEID,
				RuleIndex: ruleIndexMap[kev.CVEID],
				Level:     "error",
				Message:   sarifText{Text: msg},
				Locations: []sarifLocation{location},
				PartialFingerprints: map[string]string{
					"primaryLocationLineHash": fmt.Sprintf("%s:%s:%s",
						f.Dependency.Name, f.Dependency.Version, kev.CVEID),
				},
			})
		}
	}

	return results
}
