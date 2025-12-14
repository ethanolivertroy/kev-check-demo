package clients

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ethanolivertroy/kev-check-demo/internal/models"
)

const osvBatchURL = "https://api.osv.dev/v1/querybatch"

// OSVClient handles requests to the OSV vulnerability database
type OSVClient struct {
	httpClient *http.Client
}

// NewOSVClient creates a new OSV client
func NewOSVClient() *OSVClient {
	return &OSVClient{
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvVulnerability struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []osvVulnerability `json:"vulns"`
	} `json:"results"`
}

// QueryBatch queries OSV for vulnerabilities affecting the given dependencies
// Returns a map of dependency index -> []CVEInfo
func (c *OSVClient) QueryBatch(deps []models.Dependency) (map[int][]models.CVEInfo, error) {
	results := make(map[int][]models.CVEInfo)

	if len(deps) == 0 {
		return results, nil
	}

	// OSV batch API allows up to 1000 queries, but we'll use 100 for safety
	const batchSize = 100
	for i := 0; i < len(deps); i += batchSize {
		end := i + batchSize
		if end > len(deps) {
			end = len(deps)
		}
		chunk := deps[i:end]

		chunkResults, err := c.queryChunk(chunk)
		if err != nil {
			return nil, fmt.Errorf("failed to query OSV batch: %w", err)
		}

		// Map chunk results back to original indices
		for j, cves := range chunkResults {
			if len(cves) > 0 {
				results[i+j] = cves
			}
		}
	}

	return results, nil
}

func (c *OSVClient) queryChunk(deps []models.Dependency) (map[int][]models.CVEInfo, error) {
	req := osvBatchRequest{Queries: make([]osvQuery, len(deps))}
	for j, dep := range deps {
		req.Queries[j].Package.Name = dep.Name
		req.Queries[j].Package.Ecosystem = string(dep.Ecosystem)
		req.Queries[j].Version = dep.Version
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(osvBatchURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, err
	}

	results := make(map[int][]models.CVEInfo)
	for j, result := range batchResp.Results {
		for _, vuln := range result.Vulns {
			cves := extractCVEIDs(vuln.ID, vuln.Aliases)
			for _, cveID := range cves {
				results[j] = append(results[j], models.CVEInfo{
					ID:      cveID,
					Summary: vuln.Summary,
					Source:  "OSV",
				})
			}
		}
	}

	return results, nil
}

// extractCVEIDs extracts CVE IDs from the OSV ID and aliases
func extractCVEIDs(id string, aliases []string) []string {
	seen := make(map[string]bool)
	var cves []string

	if strings.HasPrefix(id, "CVE-") {
		if !seen[id] {
			cves = append(cves, id)
			seen[id] = true
		}
	}

	for _, alias := range aliases {
		if strings.HasPrefix(alias, "CVE-") {
			if !seen[alias] {
				cves = append(cves, alias)
				seen[alias] = true
			}
		}
	}

	return cves
}
