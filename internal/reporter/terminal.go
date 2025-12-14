package reporter

import (
	"fmt"
	"strings"

	"github.com/ethanolivertroy/kev-checker/internal/models"
)

// TerminalReporter outputs findings in a human-readable terminal format
type TerminalReporter struct{}

// Report generates terminal output for the given findings
func (r *TerminalReporter) Report(findings []models.Finding) ([]byte, error) {
	if len(findings) == 0 {
		return []byte("No KEV vulnerabilities found in dependencies.\n"), nil
	}

	var sb strings.Builder

	// Summary
	totalKEVs := 0
	ransomwareCount := 0
	for _, f := range findings {
		totalKEVs += len(f.KEVs)
		for _, kev := range f.KEVs {
			if kev.RansomwareUse {
				ransomwareCount++
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\n⚠️  KEV VULNERABILITIES FOUND\n"))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")
	sb.WriteString(fmt.Sprintf("Found %d KEV vulnerabilities in %d dependencies\n", totalKEVs, len(findings)))
	if ransomwareCount > 0 {
		sb.WriteString(fmt.Sprintf("🚨 %d vulnerabilities known to be used in ransomware campaigns\n", ransomwareCount))
	}
	sb.WriteString("\n")

	// Details
	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("📦 %s\n", f.Dependency.String()))
		sb.WriteString(fmt.Sprintf("   Source: %s", f.Dependency.SourceFile))
		if f.Dependency.Line > 0 {
			sb.WriteString(fmt.Sprintf(":%d", f.Dependency.Line))
		}
		sb.WriteString("\n")

		for _, kev := range f.KEVs {
			sb.WriteString(fmt.Sprintf("\n   🔴 %s\n", kev.CVEID))
			sb.WriteString(fmt.Sprintf("      %s - %s\n", kev.VendorProject, kev.Product))
			sb.WriteString(fmt.Sprintf("      %s\n", kev.VulnerabilityName))

			if kev.ShortDescription != "" {
				// Truncate long descriptions
				desc := kev.ShortDescription
				if len(desc) > 200 {
					desc = desc[:197] + "..."
				}
				sb.WriteString(fmt.Sprintf("      %s\n", desc))
			}

			sb.WriteString(fmt.Sprintf("      Added: %s | Due: %s\n",
				kev.DateAdded.Format("2006-01-02"),
				kev.DueDate.Format("2006-01-02")))

			if kev.EPSSScore > 0 {
				sb.WriteString(fmt.Sprintf("      EPSS: %.1f%% (percentile: %.1f%%)\n",
					kev.EPSSScore*100, kev.EPSSPercentile*100))
			}

			if kev.RansomwareUse {
				sb.WriteString("      ⚠️  Known ransomware usage\n")
			}

			if kev.RequiredAction != "" {
				action := kev.RequiredAction
				if len(action) > 100 {
					action = action[:97] + "..."
				}
				sb.WriteString(fmt.Sprintf("      Required Action: %s\n", action))
			}
		}
		sb.WriteString("\n" + strings.Repeat("-", 60) + "\n")
	}

	sb.WriteString("\nFor more information, visit: https://www.cisa.gov/known-exploited-vulnerabilities-catalog\n")

	return []byte(sb.String()), nil
}
