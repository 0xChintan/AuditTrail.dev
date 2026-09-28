// Command audittrail-verify independently re-verifies an exported evidence
// bundle: every row hash (recomputed from content), every chain link, seq
// continuity, every Ed25519 signature, every checkpoint's Merkle root and
// signature, and every RFC 3161 time-stamp token. It needs no database and
// no access to AuditTrail.
//
//	audittrail-verify bundle.json
//	audittrail-verify --tsa-roots freetsa-cacert.pem --require-anchors bundle.json
//	curl …/v1/export?format=bundle | audittrail-verify -
//	audittrail-verify --api http://localhost:8080 --api-key at_…   (fetch + verify)
//
// Exit code: 0 = verified, 1 = verification failed, 2 = usage / input error.
package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"audittrail.dev/packages/ingestion-go/internal/verify"
)

func main() {
	roots := flag.String("tsa-roots", "", "PEM file of trusted TSA root certificates (checks the TSA certificate chain)")
	sysRoots := flag.Bool("system-roots", false, "trust the OS certificate store for TSA chains")
	requireAnchors := flag.Bool("require-anchors", false, "treat checkpoints without a verified external anchor as failures")
	asJSON := flag.Bool("json", false, "print the full report as JSON")
	api := flag.String("api", "", "fetch the bundle from this AuditTrail API instead of a file")
	apiKey := flag.String("api-key", os.Getenv("AUDITTRAIL_API_KEY"), "API key for --api")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: audittrail-verify [flags] <bundle.json | ->\n       audittrail-verify [flags] --api URL --api-key KEY")
		flag.PrintDefaults()
	}
	flag.Parse()

	var data []byte
	var err error
	switch {
	case *api != "":
		req, _ := http.NewRequest("GET", strings.TrimRight(*api, "/")+"/v1/export?format=bundle", nil)
		req.Header.Set("Authorization", "Bearer "+*apiKey)
		resp, e := http.DefaultClient.Do(req)
		if e != nil {
			die(e)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			die(fmt.Errorf("API returned HTTP %d", resp.StatusCode))
		}
		data, err = io.ReadAll(resp.Body)
	case flag.NArg() == 1 && flag.Arg(0) == "-":
		data, err = io.ReadAll(os.Stdin)
	case flag.NArg() == 1:
		data, err = os.ReadFile(flag.Arg(0))
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		die(err)
	}
	var b verify.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		die(fmt.Errorf("not a bundle: %w", err))
	}

	opt := verify.Options{RequireAnchors: *requireAnchors}
	if *sysRoots {
		if opt.TSARoots, err = x509.SystemCertPool(); err != nil {
			die(err)
		}
	}
	if *roots != "" {
		pem, err := os.ReadFile(*roots)
		if err != nil {
			die(err)
		}
		if opt.TSARoots == nil {
			opt.TSARoots = x509.NewCertPool()
		}
		if !opt.TSARoots.AppendCertsFromPEM(pem) {
			die(fmt.Errorf("no certificates in %s", *roots))
		}
	}
	rep := verify.Verify(b, opt)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(rep)
	} else {
		printReport(b, rep)
	}
	if !rep.OK {
		os.Exit(1)
	}
}

func printReport(b verify.Bundle, r verify.Report) {
	fmt.Printf("AuditTrail bundle verification\n")
	fmt.Printf("  tenant        %s (%s)\n", b.Tenant.Name, b.Tenant.ID)
	fmt.Printf("  records       %d (seq %d..%d), chain start: %s\n", r.EventsChecked, r.FirstSeq, r.LastSeq, r.ChainStart)
	fmt.Printf("  hashes        %d recomputed from content\n", r.EventsChecked)
	fmt.Printf("  signatures    %d/%d valid (Ed25519)\n", r.SignaturesVerified, r.EventsChecked)
	fmt.Printf("  checkpoints   %d\n", r.CheckpointsChecked)
	for _, a := range r.Anchors {
		extra := ""
		if a.Status == "verified" {
			extra = fmt.Sprintf(" by %s at %s (cert chain: %s)", a.Authority, a.Time, a.ChainTrust)
		}
		fmt.Printf("    anchor %s: %s%s\n", a.CheckpointID, a.Status, extra)
	}
	fmt.Printf("  head hash     %s\n", r.HeadHash)
	warn := 0
	for _, is := range r.Issues {
		if is.Severity == "warning" {
			warn++
		}
	}
	if r.OK {
		fmt.Printf("\nRESULT: VERIFIED")
		if warn > 0 {
			fmt.Printf(" (%d warning(s))", warn)
		}
		fmt.Println()
	} else {
		fmt.Printf("\nRESULT: TAMPERING DETECTED\n")
		if len(r.TamperedSeqs) > 0 {
			fmt.Printf("  affected records (seq): %v\n", r.TamperedSeqs)
		}
	}
	for _, is := range r.Issues {
		loc := ""
		if is.Seq > 0 {
			loc = fmt.Sprintf("seq %d", is.Seq)
		}
		if is.EventID != "" {
			loc += " event " + is.EventID
		}
		if is.CheckpointID != "" {
			loc += " checkpoint " + is.CheckpointID
		}
		fmt.Printf("  [%s] %s %s: %s\n", strings.ToUpper(is.Severity), is.Kind, strings.TrimSpace(loc), is.Detail)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "audittrail-verify:", err)
	os.Exit(2)
}
