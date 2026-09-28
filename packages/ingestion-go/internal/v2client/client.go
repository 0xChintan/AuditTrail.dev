// Package v2client is a minimal Go client for POST /v2/events: it computes
// payload_hash, signs every request (fresh timestamp + nonce) and retries
// transport errors / 5xx / 429 with the SAME body, relying on event_id
// idempotency. Used by tests, the stress tool and the kill -9 harness.
package v2client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/contract"
	"audittrail.dev/packages/ingestion-go/internal/keys"
)

type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
	Now     func() time.Time
}

type Response struct {
	Status  int
	Body    []byte
	Receipt map[string]any
}

// Event is a convenience builder for envelopes.
type Event struct {
	EventID    string
	OccurredAt time.Time
	Agent      map[string]any
	Principal  map[string]any
	Model      map[string]any
	Delegation []map[string]any
	Action     string
	Resource   string
	Outcome    string
	Payload    map[string]any
	PII        map[string]any
}

// Body builds a valid envelope body for e (event_id generated if empty).
func (e *Event) Body() ([]byte, error) {
	if e.EventID == "" {
		e.EventID = keys.NewUUIDv7(time.Now())
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now()
	}
	var pv *contract.Value
	if e.Payload != nil {
		var err error
		if pv, err = contract.FromGo(e.Payload); err != nil {
			return nil, err
		}
	}
	m := map[string]any{
		"spec_version": "2", "event_id": e.EventID, "occurred_at": e.OccurredAt.UTC().Format(time.RFC3339Nano),
		"agent": e.Agent, "action": e.Action, "resource": e.Resource, "outcome": e.Outcome,
		"payload_hash": contract.PayloadHash(pv),
	}
	if e.Principal != nil {
		m["principal"] = e.Principal
	}
	if e.Model != nil {
		m["model"] = e.Model
	}
	if e.Delegation != nil {
		m["delegation"] = e.Delegation
	}
	if e.Payload != nil {
		m["payload"] = e.Payload
	}
	if e.PII != nil {
		m["pii"] = e.PII
	}
	return json.Marshal(m)
}

func nonce() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// SignedRequest builds a signed POST for path.
func (c *Client) SignedRequest(ctx context.Context, path string, body []byte) (*http.Request, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	ts := strconv.FormatInt(now().UnixMilli(), 10)
	n := nonce()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("X-AT-Timestamp", ts)
	req.Header.Set("X-AT-Nonce", n)
	req.Header.Set("X-AT-Signature", contract.SignRequest(c.APIKey, http.MethodPost, path, ts, n, body))
	return req, nil
}

// PostOnce sends one signed request.
func (c *Client) PostOnce(ctx context.Context, path string, body []byte) (Response, error) {
	req, err := c.SignedRequest(ctx, path, body)
	if err != nil {
		return Response{}, err
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	out := Response{Status: res.StatusCode, Body: data}
	_ = json.Unmarshal(data, &out.Receipt)
	return out, nil
}

// Submit sends body, retrying (re-signed, same body) until a final answer.
func (c *Client) Submit(ctx context.Context, body []byte) (Response, int, error) {
	retries := 0
	for attempt := 0; ; attempt++ {
		r, err := c.PostOnce(ctx, "/v2/events", body)
		if err == nil && r.Status != 429 && r.Status < 500 {
			return r, retries, nil
		}
		retries++
		if attempt > 200 {
			if err == nil {
				err = fmt.Errorf("giving up after HTTP %d", r.Status)
			}
			return r, retries, err
		}
		d := time.Duration(min(50*(attempt+1), 1000)) * time.Millisecond
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return r, retries, ctx.Err()
		}
	}
}
