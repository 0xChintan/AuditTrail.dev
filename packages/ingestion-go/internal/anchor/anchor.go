// Package anchor submits checkpoint statements to an RFC 3161 Time-Stamp
// Authority and verifies the returned tokens (Task 5.2). The TSA is an
// external party: once a checkpoint is time-stamped, nobody — including the
// AuditTrail operator — can rewrite the covered rows without the mismatch
// being provable against the TSA's signature.
package anchor

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/digitorus/timestamp"
)

type TSA struct {
	URL    string
	Client *http.Client
}

// Stamp time-stamps SHA-256(statement) and returns the DER TimeStampToken.
func (t TSA) Stamp(ctx context.Context, statement []byte) ([]byte, error) {
	req, err := timestamp.CreateRequest(bytes.NewReader(statement), &timestamp.RequestOptions{
		Hash: crypto.SHA256, Certificates: true,
	})
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/timestamp-query")
	hreq.Header.Set("Accept", "application/timestamp-reply")
	c := t.Client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := c.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("TSA %s returned HTTP %d", t.URL, resp.StatusCode)
	}
	ts, err := timestamp.ParseResponse(body)
	if err != nil {
		return nil, fmt.Errorf("TSA response: %w", err)
	}
	if err := checkImprint(ts, statement); err != nil {
		return nil, err
	}
	return ts.RawToken, nil
}

func checkImprint(ts *timestamp.Timestamp, statement []byte) error {
	if ts.HashAlgorithm != crypto.SHA256 {
		return fmt.Errorf("token uses %v, expected SHA-256", ts.HashAlgorithm)
	}
	sum := sha256.Sum256(statement)
	if !bytes.Equal(ts.HashedMessage, sum[:]) {
		return errors.New("token message imprint does not match SHA-256(statement)")
	}
	return nil
}

// Result describes a verified anchor.
type Result struct {
	Time        time.Time `json:"time"`
	Authority   string    `json:"authority"`
	SerialNo    string    `json:"serial_number"`
	ChainTrust  string    `json:"chain_trust"` // "verified" | "not_checked"
	Certificate string    `json:"certificate_subject"`
}

// Verify checks a base64 TimeStampToken against the statement bytes:
// CMS signature (by the embedded TSA certificate), message imprint, and — if
// roots is non-nil — that the TSA certificate chains to a trusted root.
func Verify(tokenB64 string, statement []byte, roots *x509.CertPool) (Result, error) {
	der, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		return Result{}, fmt.Errorf("anchor proof is not base64: %w", err)
	}
	ts, err := timestamp.Parse(der) // verifies the CMS signature when certs are embedded
	if err != nil {
		return Result{}, fmt.Errorf("invalid TimeStampToken: %w", err)
	}
	if !ts.AddTSACertificate || len(ts.Certificates) == 0 {
		return Result{}, errors.New("TimeStampToken carries no TSA certificate; cannot verify signature")
	}
	if err := checkImprint(ts, statement); err != nil {
		return Result{}, err
	}
	// The signer is the end-entity (non-CA) certificate with the
	// timeStamping EKU; intermediates may carry the EKU too.
	signer := ts.Certificates[0]
	for _, c := range ts.Certificates {
		for _, u := range c.ExtKeyUsage {
			if u == x509.ExtKeyUsageTimeStamping && !c.IsCA {
				signer = c
			}
		}
	}
	res := Result{Time: ts.Time, Authority: signer.Subject.CommonName, SerialNo: ts.SerialNumber.String(),
		ChainTrust: "not_checked", Certificate: signer.Subject.String()}
	if res.Authority == "" {
		res.Authority = signer.Subject.String()
	}
	if roots != nil {
		inter := x509.NewCertPool()
		for _, c := range ts.Certificates {
			inter.AddCert(c)
		}
		if _, err := signer.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
			CurrentTime: ts.Time, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}); err != nil {
			return res, fmt.Errorf("TSA certificate not trusted: %w", err)
		}
		res.ChainTrust = "verified"
	}
	return res, nil
}
