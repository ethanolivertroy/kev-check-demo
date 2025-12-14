package reporter

import (
	"encoding/json"

	"github.com/ethanolivertroy/kev-check-demo/internal/models"
)

// JSONReporter outputs findings in JSON format
type JSONReporter struct{}

// jsonOutput represents the JSON output structure
type jsonOutput struct {
	Summary  jsonSummary   `json:"summary"`
	Findings []jsonFinding `json:"findings"`
}

type jsonSummary struct {
	TotalFindings      int `json:"total_findings"`
	TotalKEVs          int `json:"total_kevs"`
	RansomwareRelated  int `json:"ransomware_related"`
	AffectedPackages   int `json:"affected_packages"`
}

type jsonFinding struct {
	Package    jsonPackage `json:"package"`
	SourceFile string      `json:"source_file"`
	Line       int         `json:"line,omitempty"`
	KEVs       []jsonKEV   `json:"kevs"`
}

type jsonPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type jsonKEV struct {
	CVEID             string   `json:"cve_id"`
	VendorProject     string   `json:"vendor_project"`
	Product           string   `json:"product"`
	VulnerabilityName string   `json:"vulnerability_name"`
	Description       string   `json:"description"`
	DateAdded         string   `json:"date_added"`
	DueDate           string   `json:"due_date"`
	RequiredAction    string   `json:"required_action"`
	RansomwareUse     bool     `json:"ransomware_use"`
	CWEs              []string `json:"cwes,omitempty"`
	EPSSScore         float64  `json:"epss_score,omitempty"`
	EPSSPercentile    float64  `json:"epss_percentile,omitempty"`
}

// Report generates JSON output for the given findings
func (r *JSONReporter) Report(findings []models.Finding) ([]byte, error) {
	output := jsonOutput{
		Summary: jsonSummary{
			TotalFindings:    len(findings),
			AffectedPackages: len(findings),
		},
		Findings: make([]jsonFinding, 0, len(findings)),
	}

	for _, f := range findings {
		jf := jsonFinding{
			Package: jsonPackage{
				Name:      f.Dependency.Name,
				Version:   f.Dependency.Version,
				Ecosystem: string(f.Dependency.Ecosystem),
			},
			SourceFile: f.Dependency.SourceFile,
			Line:       f.Dependency.Line,
			KEVs:       make([]jsonKEV, 0, len(f.KEVs)),
		}

		for _, kev := range f.KEVs {
			output.Summary.TotalKEVs++
			if kev.RansomwareUse {
				output.Summary.RansomwareRelated++
			}

			jk := jsonKEV{
				CVEID:             kev.CVEID,
				VendorProject:     kev.VendorProject,
				Product:           kev.Product,
				VulnerabilityName: kev.VulnerabilityName,
				Description:       kev.ShortDescription,
				DateAdded:         kev.DateAdded.Format("2006-01-02"),
				DueDate:           kev.DueDate.Format("2006-01-02"),
				RequiredAction:    kev.RequiredAction,
				RansomwareUse:     kev.RansomwareUse,
				CWEs:              kev.CWEs,
				EPSSScore:         kev.EPSSScore,
				EPSSPercentile:    kev.EPSSPercentile,
			}
			jf.KEVs = append(jf.KEVs, jk)
		}

		output.Findings = append(output.Findings, jf)
	}

	return json.MarshalIndent(output, "", "  ")
}
