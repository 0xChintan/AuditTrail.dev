package anchor

import (
	"context"
	"os"
	"testing"
	"time"
)

// Live test against public TSAs; run with ANCHOR_LIVE=1.
func TestLiveTSAs(t *testing.T) {
	if os.Getenv("ANCHOR_LIVE") == "" {
		t.Skip("set ANCHOR_LIVE=1")
	}
	stmt := []byte(`{"type":"audittrail.checkpoint.v1","test":true}`)
	for _, u := range []string{"https://freetsa.org/tsr", "http://timestamp.digicert.com", "http://timestamp.sectigo.com"} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		tok, err := TSA{URL: u}.Stamp(ctx, stmt)
		cancel()
		if err != nil {
			t.Logf("%s: %v", u, err)
			continue
		}
		res, err := Verify(b64(tok), stmt, nil)
		t.Logf("%s: ok token=%dB authority=%q time=%s verifyErr=%v", u, len(tok), res.Authority, res.Time, err)
		if _, err := Verify(b64(tok), []byte("tampered"), nil); err == nil {
			t.Errorf("%s: tampered statement accepted", u)
		}
	}
}
