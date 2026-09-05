package upload

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MichalAFerber/sniffer/internal/obs"
)

func TestSendIngest(t *testing.T) {
	var got obs.Batch
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/ingest" {
			t.Errorf("path %s", r.URL.Path)
		}
		auth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("json: %v", err)
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()

	c := New(srv.URL, "sekrit", obs.Sensor{ID: "pi", OS: "linux", Arch: "arm64", Version: "test"}, "")
	err := c.Send(context.Background(), []obs.Host{{
		IP: "192.168.1.5", FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer sekrit" {
		t.Fatalf("auth %q", auth)
	}
	if got.Sensor.ID != "pi" || len(got.Hosts) != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestSendNoAPIIsLocalOnly(t *testing.T) {
	c := New("", "", obs.Sensor{ID: "x"}, "")
	if err := c.Send(context.Background(), []obs.Host{{IP: "1.2.3.4"}}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
}
