package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ethanolivertroy/kev-checker/internal/models"
	"github.com/ethanolivertroy/kev-checker/internal/reporter"
	"github.com/ethanolivertroy/kev-checker/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	flagOutput    string
	flagFormat    string
	flagThreshold float64
	flagNoFail    bool
	flagNoCache   bool
	flagTimeout   int
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "kev-checker [paths...]",
	Short: "Check dependencies for CISA Known Exploited Vulnerabilities (KEV)",
	Long: `kev-checker scans your project dependencies and identifies any that have
known exploited vulnerabilities (KEV) tracked by CISA.

It supports multiple ecosystems:
  - Python: requirements.txt, pyproject.toml
  - Node.js: package.json, package-lock.json
  - Go: go.mod

The tool queries the OSV database to find CVEs affecting your dependencies,
then cross-references them against the CISA KEV catalog and enriches the
results with EPSS (Exploit Prediction Scoring System) scores.

Examples:
  # Scan current directory
  kev-checker

  # Scan specific paths
  kev-checker ./app ./services

  # Output as JSON
  kev-checker --format json

  # Output SARIF for GitHub Code Scanning
  kev-checker --format sarif --output results.sarif

  # Don't fail on KEV findings (exit 0 regardless)
  kev-checker --no-fail

  # Only report if EPSS score >= 10%
  kev-checker --epss-threshold 0.1`,
	RunE: runCheck,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Output file path (default: stdout)")
	rootCmd.Flags().StringVarP(&flagFormat, "format", "f", "terminal", "Output format: terminal, json, sarif")
	rootCmd.Flags().Float64Var(&flagThreshold, "epss-threshold", 0, "Only report KEVs with EPSS >= threshold (0-1)")
	rootCmd.Flags().BoolVar(&flagNoFail, "no-fail", false, "Don't exit with error code if KEVs found")
	rootCmd.Flags().BoolVar(&flagNoCache, "no-cache", false, "Disable KEV data caching")
	rootCmd.Flags().IntVar(&flagTimeout, "timeout", 60, "HTTP request timeout in seconds")
}

func runCheck(cmd *cobra.Command, args []string) error {
	paths := args
	if len(paths) == 0 {
		paths = []string{"."}
	}

	config := &models.Config{
		Paths:         paths,
		OutputFormat:  flagFormat,
		OutputFile:    flagOutput,
		FailOnKEV:     !flagNoFail,
		EPSSThreshold: flagThreshold,
		NoCache:       flagNoCache,
		CacheTTL:      24 * time.Hour,
		Timeout:       time.Duration(flagTimeout) * time.Second,
	}

	// Create scanner
	s, err := scanner.New(config)
	if err != nil {
		return fmt.Errorf("failed to initialize scanner: %w", err)
	}

	// Run scan
	ctx := context.Background()
	findings, err := s.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Generate report
	rep := reporter.Get(config.OutputFormat)
	output, err := rep.Report(findings)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Write output
	if config.OutputFile != "" {
		if err := os.WriteFile(config.OutputFile, output, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", config.OutputFile)
	} else {
		fmt.Print(string(output))
	}

	// Exit with error code if KEVs found and not disabled
	if len(findings) > 0 && config.FailOnKEV {
		os.Exit(1)
	}

	return nil
}
