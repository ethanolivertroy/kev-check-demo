package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ethanolivertroy/kev-checker/internal/cache"
	"github.com/ethanolivertroy/kev-checker/internal/clients"
	"github.com/ethanolivertroy/kev-checker/internal/models"
	"github.com/ethanolivertroy/kev-checker/internal/parsers"
)

// Scanner orchestrates the vulnerability scanning process
type Scanner struct {
	config     *models.Config
	parsers    []parsers.Parser
	kevClient  *clients.KEVClient
	osvClient  *clients.OSVClient
	epssClient *clients.EPSSClient
}

// New creates a new Scanner with the given configuration
func New(config *models.Config) (*Scanner, error) {
	var c *cache.Cache
	var err error

	if !config.NoCache {
		c, err = cache.New("kev-checker", config.CacheTTL)
		if err != nil {
			// Non-fatal: continue without cache
			c = nil
		}
	}

	return &Scanner{
		config:     config,
		parsers:    parsers.GetAllParsers(),
		kevClient:  clients.NewKEVClient(c),
		osvClient:  clients.NewOSVClient(),
		epssClient: clients.NewEPSSClient(),
	}, nil
}

// Scan performs the full vulnerability scan
func (s *Scanner) Scan(ctx context.Context) ([]models.Finding, error) {
	// Step 1: Discover and parse dependency files
	deps, err := s.discoverDependencies()
	if err != nil {
		return nil, fmt.Errorf("failed to discover dependencies: %w", err)
	}

	if len(deps) == 0 {
		return nil, nil
	}

	// Step 2: Fetch KEV catalog (cached)
	kevCatalog, err := s.kevClient.FetchKEVCatalog()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch KEV catalog: %w", err)
	}

	// Step 3: Query OSV for CVEs affecting dependencies
	cvesByDep, err := s.osvClient.QueryBatch(deps)
	if err != nil {
		return nil, fmt.Errorf("failed to query OSV: %w", err)
	}

	// Step 4: Cross-reference with KEV and build findings
	var findings []models.Finding
	var allKEVCVEs []string

	for depIdx, cves := range cvesByDep {
		dep := deps[depIdx]
		finding := models.Finding{
			Dependency: dep,
			CVEs:       cves,
		}

		// Check each CVE against KEV catalog
		for _, cve := range cves {
			if kevInfo, isKEV := kevCatalog[cve.ID]; isKEV {
				finding.KEVs = append(finding.KEVs, kevInfo)
				allKEVCVEs = append(allKEVCVEs, cve.ID)
			}
		}

		// Only include findings that have KEV matches
		if len(finding.KEVs) > 0 {
			findings = append(findings, finding)
		}
	}

	// Step 5: Enrich with EPSS scores
	if len(allKEVCVEs) > 0 {
		epssScores, _ := s.epssClient.FetchScores(allKEVCVEs)
		for i := range findings {
			for j := range findings[i].KEVs {
				if score, ok := epssScores[findings[i].KEVs[j].CVEID]; ok {
					findings[i].KEVs[j].EPSSScore = score.Score
					findings[i].KEVs[j].EPSSPercentile = score.Percentile
				}
			}
		}
	}

	// Step 6: Filter by EPSS threshold if configured
	if s.config.EPSSThreshold > 0 {
		var filtered []models.Finding
		for _, f := range findings {
			var filteredKEVs []models.KEVInfo
			for _, kev := range f.KEVs {
				if kev.EPSSScore >= s.config.EPSSThreshold {
					filteredKEVs = append(filteredKEVs, kev)
				}
			}
			if len(filteredKEVs) > 0 {
				f.KEVs = filteredKEVs
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	return findings, nil
}

// discoverDependencies walks the configured paths and parses dependency files
func (s *Scanner) discoverDependencies() ([]models.Dependency, error) {
	var allDeps []models.Dependency

	for _, path := range s.config.Paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("failed to stat path %s: %w", path, err)
		}

		if !info.IsDir() {
			// Single file
			deps, err := s.parseFile(path)
			if err != nil {
				return nil, err
			}
			allDeps = append(allDeps, deps...)
			continue
		}

		// Directory walk
		err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			// Skip common non-source directories
			if d.IsDir() {
				name := d.Name()
				if name == "node_modules" || name == ".git" || name == "vendor" ||
					name == "__pycache__" || name == ".venv" || name == "venv" {
					return filepath.SkipDir
				}
				return nil
			}

			deps, err := s.parseFile(p)
			if err != nil {
				// Log but don't fail on individual file parse errors
				return nil
			}
			allDeps = append(allDeps, deps...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return allDeps, nil
}

// parseFile attempts to parse a file with any matching parser
func (s *Scanner) parseFile(path string) ([]models.Dependency, error) {
	filename := filepath.Base(path)

	for _, parser := range s.parsers {
		if parser.CanParse(filename) {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			return parser.Parse(path, content)
		}
	}

	return nil, nil // No matching parser
}
