package clients

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ethanolivertroy/kev-checker/internal/cache"
	"github.com/ethanolivertroy/kev-checker/internal/models"
)

const kevURL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"

// KEVClient handles requests to the CISA KEV catalog
type KEVClient struct {
	httpClient *http.Client
	cache      *cache.Cache
}

// NewKEVClient creates a new KEV client
func NewKEVClient(c *cache.Cache) *KEVClient {
	return &KEVClient{
		httpClient: &http.Client{Timeout: 60 * time.Second},
		cache:      c,
	}
}

// KEVResponse represents the top-level JSON response from CISA KEV catalog
type KEVResponse struct {
	Title           string              `json:"title"`
	CatalogVersion  string              `json:"catalogVersion"`
	DateReleased    string              `json:"dateReleased"`
	Count           int                 `json:"count"`
	Vulnerabilities []VulnerabilityJSON `json:"vulnerabilities"`
}

// VulnerabilityJSON represents a single vulnerability entry from the API
type VulnerabilityJSON struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`
}

// FetchKEVCatalog fetches the KEV catalog and returns a map of CVE ID -> KEVInfo
func (c *KEVClient) FetchKEVCatalog() (map[string]models.KEVInfo, error) {
	var data []byte

	// Check cache first
	if c.cache != nil {
		if cached, ok := c.cache.Get(kevURL); ok {
			data = cached
		}
	}

	// Fetch from remote if not cached
	if data == nil {
		resp, err := c.httpClient.Get(kevURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch KEV data: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}

		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		// Cache the response
		if c.cache != nil {
			c.cache.Set(kevURL, data)
		}
	}

	return c.parseKEVData(data)
}

func (c *KEVClient) parseKEVData(data []byte) (map[string]models.KEVInfo, error) {
	var kevResp KEVResponse
	if err := json.Unmarshal(data, &kevResp); err != nil {
		return nil, fmt.Errorf("failed to parse KEV data: %w", err)
	}

	catalog := make(map[string]models.KEVInfo, len(kevResp.Vulnerabilities))
	for _, v := range kevResp.Vulnerabilities {
		kev := models.KEVInfo{
			CVEID:             v.CVEID,
			VendorProject:     v.VendorProject,
			Product:           v.Product,
			VulnerabilityName: v.VulnerabilityName,
			ShortDescription:  v.ShortDescription,
			RequiredAction:    v.RequiredAction,
			RansomwareUse:     v.KnownRansomwareCampaignUse == "Known",
			CWEs:              v.CWEs,
			Notes:             v.Notes,
		}
		kev.DateAdded, _ = time.Parse("2006-01-02", v.DateAdded)
		kev.DueDate, _ = time.Parse("2006-01-02", v.DueDate)
		catalog[v.CVEID] = kev
	}

	return catalog, nil
}
