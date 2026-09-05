package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/MichalAFerber/sniffer/internal/obs"
)

type Client struct {
	URL    string
	Token  string
	Sensor obs.Sensor
	Log    string // optional JSONL spool path
	HTTP   *http.Client

	mu     sync.Mutex
	failed int
}

func New(url, token string, sensor obs.Sensor, logPath string) *Client {
	return &Client{
		URL:    url,
		Token:  token,
		Sensor: sensor,
		Log:    logPath,
		HTTP:   &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *Client) Send(ctx context.Context, hosts []obs.Host, services []obs.Service, flows []obs.Flow, names []obs.Name) error {
	if len(hosts)+len(services)+len(flows)+len(names) == 0 {
		return nil
	}
	batch := obs.Batch{
		Sensor:   c.Sensor,
		SentAt:   time.Now().UTC(),
		Hosts:    hosts,
		Services: services,
		Flows:    flows,
		Names:    names,
	}
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	if c.Log != "" {
		_ = c.appendLog(body)
	}
	if c.URL == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/v1/ingest", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "netmapd/"+c.Sensor.Version)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		c.mu.Lock()
		c.failed++
		c.mu.Unlock()
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		c.mu.Lock()
		c.failed++
		c.mu.Unlock()
		return fmt.Errorf("ingest %s", resp.Status)
	}
	c.mu.Lock()
	c.failed = 0
	c.mu.Unlock()
	return nil
}

func (c *Client) Heartbeat(ctx context.Context, hosts, services, flows, names int) error {
	if c.URL == "" {
		return nil
	}
	payload, _ := json.Marshal(map[string]any{
		"sensor":    c.Sensor,
		"sent_at":   time.Now().UTC(),
		"hosts":     hosts,
		"services":  services,
		"flows":     flows,
		"names":     names,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/v1/heartbeat", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("heartbeat %s", resp.Status)
	}
	return nil
}

func (c *Client) Failures() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failed
}

func (c *Client) appendLog(body []byte) error {
	f, err := os.OpenFile(c.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(body, '\n'))
	return err
}
