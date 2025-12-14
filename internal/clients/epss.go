package clients

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethanolivertroy/kev-check-demo/internal/models"
)

const epssURL = "https://api.first.org/data/v1/epss"

// EPSSClient handles requests to the EPSS API
type EPSSClient struct {
	httpClient *http.Client
}

// NewEPSSClient creates a new EPSS client
func NewEPSSClient() *EPSSClient {
	return &EPSSClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// EPSSResponse represents the response from the EPSS API
type EPSSResponse struct {
	Status     string     `json:"status"`
	StatusCode int        `json:"status-code"`
	Version    string     `json:"version"`
	Total      int        `json:"total"`
	Data       []EPSSData `json:"data"`
}

// EPSSData represents a single EPSS score entry
type EPSSData struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

// FetchScores fetches EPSS scores for the given CVE IDs
// Returns a map of CVE ID -> EPSSScore
func (c *EPSSClient) FetchScores(cveIDs []string) (map[string]models.EPSSScore, error) {
	scores := make(map[string]models.EPSSScore)

	if len(cveIDs) == 0 {
		return scores, nil
	}

	// EPSS API allows batch queries, chunk to avoid URL length issues
	const chunkSize = 100
	for i := 0; i < len(cveIDs); i += chunkSize {
		end := i + chunkSize
		if end > len(cveIDs) {
			end = len(cveIDs)
		}
		chunk := cveIDs[i:end]

		url := fmt.Sprintf("%s?cve=%s", epssURL, strings.Join(chunk, ","))
		resp, err := c.httpClient.Get(url)
		if err != nil {
			// Don't fail completely on EPSS errors, just skip
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		var epssResp EPSSResponse
		if err := json.NewDecoder(resp.Body).Decode(&epssResp); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		for _, data := range epssResp.Data {
			score, _ := strconv.ParseFloat(data.EPSS, 64)
			percentile, _ := strconv.ParseFloat(data.Percentile, 64)
			scores[data.CVE] = models.EPSSScore{
				Score:      score,
				Percentile: percentile,
			}
		}
	}

	return scores, nil
}
