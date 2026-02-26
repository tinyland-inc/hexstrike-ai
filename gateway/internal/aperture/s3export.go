package aperture

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// UsageReport contains aggregated usage data from Aperture.
type UsageReport struct {
	Period     string         `json:"period"`
	TotalCalls int           `json:"total_calls"`
	ByCaller   map[string]int `json:"by_caller"`
	ByTool     map[string]int `json:"by_tool"`
	Errors     int           `json:"errors"`
}

// ExportClient periodically pulls usage data from Aperture for dashboards.
type ExportClient struct {
	BaseURL    string
	HTTPClient *http.Client
	stopCh     chan struct{}
}

// NewExportClient creates an Aperture export client.
func NewExportClient(baseURL string) *ExportClient {
	return &ExportClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		stopCh: make(chan struct{}),
	}
}

// FetchReport pulls the latest usage report from Aperture.
func (c *ExportClient) FetchReport(period string) (*UsageReport, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("export URL not configured")
	}

	url := fmt.Sprintf("%s/api/v1/usage/report?period=%s", c.BaseURL, period)
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch report: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aperture report: %d", resp.StatusCode)
	}

	var report UsageReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode report: %w", err)
	}

	return &report, nil
}

// StartPeriodicExport fetches reports periodically and calls the handler.
func (c *ExportClient) StartPeriodicExport(interval time.Duration, handler func(*UsageReport)) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				report, err := c.FetchReport("1h")
				if err != nil {
					log.Printf("aperture export error: %v", err)
					continue
				}
				handler(report)
			}
		}
	}()
}

// Stop terminates the periodic export.
func (c *ExportClient) Stop() {
	close(c.stopCh)
}
