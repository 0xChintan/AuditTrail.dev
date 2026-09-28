// Package verify independently re-checks an exported evidence bundle
// (Task 5.3). It needs nothing but the bundle: no database, no API, no trust
// in AuditTrail.dev beyond the public keys in the bundle — and those are
// themselves pinned by the externally anchored checkpoint signatures.
package verify

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"sort"

	"audittrail.dev/packages/ingestion-go/internal/anchor"
	"audittrail.dev/packages/ingestion-go/internal/canon"
	"audittrail.dev/packages/ingestion-go/internal/keys"
	"audittrail.dev/packages/ingestion-go/internal/ledger"
	"audittrail.dev/packages/ingestion-go/internal/merkle"
)

const BundleFormat = "audittrail.bundle.v1"

type PublicKey struct {
	KeyID     string  `json:"key_id"`
	Algorithm string  `json:"algorithm"`
	PublicKey string  `json:"public_key"`
	CreatedAt string  `json:"created_at"`
	RetiredAt *string `json:"retired_at"`
}

// Bundle is the portable evidence package produced by /v1/export.
type Bundle struct {
	Format      string              `json:"format"`
	GeneratedAt string              `json:"generated_at"`
	Tenant      BundleTenant        `json:"tenant"`
	PublicKeys  []PublicKey         `json:"public_keys"`
	Events      []ledger.Record     `json:"events"`
	Checkpoints []ledger.Checkpoint `json:"checkpoints"`
	Template    *json.RawMessage    `json:"template,omitempty"`
}

type BundleTenant struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	RetentionDays int    `json:"retention_days"`
	LegalHold     bool   `json:"legal_hold"`
}

type Issue struct {
	Severity     string `json:"severity"` // error | warning
	Kind         string `json:"kind"`
	Seq          int64  `json:"seq,omitempty"`
	EventID      string `json:"event_id,omitempty"`
	CheckpointID string `json:"checkpoint_id,omitempty"`
	Detail       string `json:"detail"`
}

type AnchorResult struct {
	CheckpointID string `json:"checkpoint_id"`
	Status       string `json:"status"` // verified | pending | failed | disabled | missing
	Authority    string `json:"authority,omitempty"`
	Time         string `json:"time,omitempty"`
	ChainTrust   string `json:"chain_trust,omitempty"`
}

type Report struct {
	OK                 bool           `json:"ok"`
	TenantID           string         `json:"tenant_id"`
	EventsChecked      int            `json:"events_checked"`
	SignaturesVerified int            `json:"signatures_verified"`
	CheckpointsChecked int            `json:"checkpoints_checked"`
	FirstSeq           int64          `json:"first_seq"`
	LastSeq            int64          `json:"last_seq"`
	HeadHash           string         `json:"head_hash"`
	ChainStart         string         `json:"chain_start"`
	Anchors            []AnchorResult `json:"anchors"`
	TamperedSeqs       []int64        `json:"tampered_seqs"`
	Issues             []Issue        `json:"issues"`
}

type Options struct {
	TSARoots       *x509.CertPool // nil = verify TSA signature but not its chain of trust
	RequireAnchors bool           // pending/missing anchors become errors instead of warnings
}

func (r *Report) add(sev, kind string, seq int64, evID, cpID, format string, args ...any) {
	r.Issues = append(r.Issues, Issue{Severity: sev, Kind: kind, Seq: seq, EventID: evID, CheckpointID: cpID, Detail: fmt.Sprintf(format, args...)})
	if sev == "error" {
		r.OK = false
	}
}

func (r *Report) tampered(seq int64) {
	for _, s := range r.TamperedSeqs {
		if s == seq {
			return
		}
	}
	r.TamperedSeqs = append(r.TamperedSeqs, seq)
}

// Verify runs every check in SPEC §6 and localizes failures to seq numbers.
func Verify(b Bundle, opt Options) Report {
	rep := Report{OK: true, TenantID: b.Tenant.ID, Issues: []Issue{}, TamperedSeqs: []int64{}, Anchors: []AnchorResult{}}
	if b.Format != BundleFormat {
		rep.add("error", "bad_format", 0, "", "", "unsupported bundle format %q", b.Format)
		return rep
	}
	pub := map[string]string{}
	for _, k := range b.PublicKeys {
		pub[k.KeyID] = k.PublicKey
	}

	evs := append([]ledger.Record(nil), b.Events...)
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Seq < evs[j].Seq })
	bySeq := map[int64]ledger.Record{}
	for _, e := range evs {
		if _, dup := bySeq[e.Seq]; dup {
			rep.add("error", "duplicate_seq", e.Seq, e.ID, "", "seq %d appears more than once", e.Seq)
			rep.tampered(e.Seq)
		}
		bySeq[e.Seq] = e
	}

	// Checkpoints first: they pin head hashes we may need as chain start.
	cps := append([]ledger.Checkpoint(nil), b.Checkpoints...)
	sort.Slice(cps, func(i, j int) bool { return cps[i].FirstSeq < cps[j].FirstSeq })
	cpValid := map[string]bool{} // checkpoint id -> statement + signature OK
	var rootMismatch [][2]int64
	for i, cp := range cps {
		rep.CheckpointsChecked++
		ok := verifyCheckpointStatement(&rep, b.Tenant.ID, cp, pub)
		cpValid[cp.ID] = ok
		if i > 0 && cps[i-1].LastSeq+1 == cp.FirstSeq && cps[i-1].HeadHash != cp.PrevCheckpointHead {
			rep.add("error", "checkpoint_chain_broken", cp.FirstSeq, "", cp.ID,
				"checkpoint prev_checkpoint_head does not equal the previous checkpoint's head_hash")
		}
		if cp.FirstSeq == 1 && cp.PrevCheckpointHead != canon.Genesis {
			rep.add("error", "checkpoint_chain_broken", 1, "", cp.ID, "first checkpoint does not start at genesis")
		}
		rep.Anchors = append(rep.Anchors, verifyAnchor(&rep, cp, opt))

		// Merkle root over the stored row hashes, if the bundle has the full range.
		hashes := make([]string, 0, cp.RowCount)
		complete := true
		for s := cp.FirstSeq; s <= cp.LastSeq; s++ {
			e, ok := bySeq[s]
			if !ok {
				complete = false
				break
			}
			hashes = append(hashes, e.Hash)
		}
		if !complete {
			if len(evs) == 0 || cp.LastSeq < evs[0].Seq || cp.FirstSeq > evs[len(evs)-1].Seq {
				continue // checkpoint outside the exported rows (e.g. the chain-start anchor)
			}
			var missing []int64
			for s := cp.FirstSeq; s <= cp.LastSeq; s++ {
				if _, ok := bySeq[s]; !ok {
					missing = append(missing, s)
				}
			}
			if evs[0].Seq <= cp.FirstSeq && evs[len(evs)-1].Seq >= cp.LastSeq {
				// The bundle spans the whole signed range, yet rows are absent:
				// they were deleted after being checkpointed.
				rep.add("error", "checkpoint_rows_missing", missing[0], "", cp.ID,
					"%d row(s) covered by signed checkpoint %d..%d are missing: seq %v", len(missing), cp.FirstSeq, cp.LastSeq, missing)
				for _, s := range missing {
					rep.tampered(s)
				}
			} else {
				rep.add("warning", "checkpoint_partial", 0, "", cp.ID,
					"bundle holds only part of checkpoint range %d..%d; Merkle root not recomputed", cp.FirstSeq, cp.LastSeq)
			}
			continue
		}
		root, err := merkle.RootHex(hashes)
		if err != nil || root != cp.MerkleRoot {
			rep.add("error", "checkpoint_root_mismatch", cp.FirstSeq, "", cp.ID,
				"rows %d..%d no longer match the signed Merkle root: rows were altered after checkpointing", cp.FirstSeq, cp.LastSeq)
			// Localized after the row pass: if no row in the range shows
			// row-level evidence (bad hash/signature/link), the whole range
			// was consistently rewritten (e.g. with a stolen key) and is flagged.
			rootMismatch = append(rootMismatch, [2]int64{cp.FirstSeq, cp.LastSeq})
		}
		if last, ok := bySeq[cp.LastSeq]; ok && last.Hash != cp.HeadHash {
			rep.add("error", "checkpoint_head_mismatch", cp.LastSeq, last.ID, cp.ID,
				"row %d hash differs from the checkpoint's signed head_hash", cp.LastSeq)
		}
	}

	if len(evs) == 0 {
		return rep
	}
	rep.FirstSeq, rep.LastSeq = evs[0].Seq, evs[len(evs)-1].Seq
	rep.HeadHash = evs[len(evs)-1].Hash

	// Where must the chain start?
	expectedPrev := ""
	if evs[0].Seq == 1 {
		expectedPrev = canon.Genesis
		rep.ChainStart = "genesis"
	} else {
		for _, cp := range cps {
			if cp.LastSeq == evs[0].Seq-1 && cpValid[cp.ID] {
				expectedPrev = cp.HeadHash
				rep.ChainStart = "checkpoint:" + cp.ID
			}
		}
		if expectedPrev == "" {
			rep.ChainStart = "unanchored"
			rep.add("warning", "chain_start_unanchored", evs[0].Seq, evs[0].ID, "",
				"bundle starts at seq %d with no signed checkpoint ending at seq %d; the first link cannot be checked", evs[0].Seq, evs[0].Seq-1)
		}
	}

	var prev *ledger.Record
	for i := range evs {
		e := evs[i]
		rep.EventsChecked++
		if e.TenantID != b.Tenant.ID {
			rep.add("error", "wrong_tenant", e.Seq, e.ID, "", "row belongs to tenant %s", e.TenantID)
			rep.tampered(e.Seq)
		}
		// 1. content -> hash (rules of the row's spec_version)
		recomputed, err := e.RecomputeHash()
		if err == nil && !e.PayloadIntact() {
			rep.add("error", "payload_tampered", e.Seq, e.ID, "", "row %d payload does not match its payload_hash", e.Seq)
			rep.tampered(e.Seq)
		}
		if err != nil {
			rep.add("error", "unhashable_row", e.Seq, e.ID, "", "cannot canonicalize row: %v", err)
			rep.tampered(e.Seq)
		} else if recomputed != e.Hash {
			rep.add("error", "content_tampered", e.Seq, e.ID, "",
				"row %d content does not hash to its stored hash (stored %s…, recomputed %s…)", e.Seq, e.Hash[:12], recomputed[:12])
			rep.tampered(e.Seq)
		}
		// 2. link
		if prev != nil {
			if e.Seq != prev.Seq+1 {
				rep.add("error", "seq_gap", prev.Seq+1, e.ID, "", "seq jumps from %d to %d: rows %d..%d are missing", prev.Seq, e.Seq, prev.Seq+1, e.Seq-1)
				for s := prev.Seq + 1; s < e.Seq; s++ {
					rep.tampered(s)
				}
			}
			if e.PreviousHash != prev.Hash && e.Seq == prev.Seq+1 {
				rep.add("error", "link_broken", e.Seq, e.ID, "",
					"row %d previous_hash does not match row %d hash", e.Seq, prev.Seq)
				rep.tampered(e.Seq)
			}
		} else if expectedPrev != "" && e.PreviousHash != expectedPrev {
			rep.add("error", "link_broken", e.Seq, e.ID, "", "first row does not link to %s", rep.ChainStart)
			rep.tampered(e.Seq)
		}
		// 3. signature
		pk, ok := pub[e.KeyID]
		if !ok {
			rep.add("error", "unknown_key", e.Seq, e.ID, "", "signing key %s not in bundle", e.KeyID)
		} else if !keys.Verify(pk, e.SigningMessage(), e.Signature) {
			rep.add("error", "bad_signature", e.Seq, e.ID, "", "Ed25519 signature does not verify")
			rep.tampered(e.Seq)
		} else {
			rep.SignaturesVerified++
		}
		prev = &evs[i]
	}
	for _, rg := range rootMismatch {
		evidence := false
		for _, s := range rep.TamperedSeqs {
			if s >= rg[0] && s <= rg[1] {
				evidence = true
			}
		}
		if !evidence {
			for s := rg[0]; s <= rg[1]; s++ {
				rep.tampered(s)
			}
		}
	}
	sort.Slice(rep.TamperedSeqs, func(i, j int) bool { return rep.TamperedSeqs[i] < rep.TamperedSeqs[j] })
	return rep
}

func verifyCheckpointStatement(rep *Report, tenantID string, cp ledger.Checkpoint, pub map[string]string) bool {
	var st canon.CheckpointStatement
	if err := json.Unmarshal([]byte(cp.Statement), &st); err != nil {
		rep.add("error", "checkpoint_statement_invalid", cp.FirstSeq, "", cp.ID, "statement is not JSON: %v", err)
		return false
	}
	canonBytes, err := st.Bytes()
	if err != nil || string(canonBytes) != cp.Statement {
		rep.add("error", "checkpoint_statement_invalid", cp.FirstSeq, "", cp.ID, "statement is not in canonical form")
		return false
	}
	ok := true
	mismatch := func(field string) {
		rep.add("error", "checkpoint_field_mismatch", cp.FirstSeq, "", cp.ID, "column %s differs from the signed statement", field)
		ok = false
	}
	if st.Type != canon.CheckpointType {
		mismatch("type")
	}
	if st.TenantID != tenantID || cp.TenantID != tenantID {
		mismatch("tenant_id")
	}
	if st.FirstSeq != cp.FirstSeq {
		mismatch("first_seq")
	}
	if st.LastSeq != cp.LastSeq {
		mismatch("last_seq")
	}
	if st.RowCount != cp.RowCount {
		mismatch("row_count")
	}
	if st.MerkleRoot != cp.MerkleRoot {
		mismatch("merkle_root")
	}
	if st.HeadHash != cp.HeadHash {
		mismatch("head_hash")
	}
	if st.PrevCheckpointHead != cp.PrevCheckpointHead {
		mismatch("prev_checkpoint_head")
	}
	pk, found := pub[cp.KeyID]
	if !found {
		rep.add("error", "unknown_key", cp.FirstSeq, "", cp.ID, "checkpoint signing key %s not in bundle", cp.KeyID)
		return false
	}
	if !keys.Verify(pk, []byte(cp.Statement), cp.Signature) {
		rep.add("error", "checkpoint_bad_signature", cp.FirstSeq, "", cp.ID, "checkpoint signature does not verify")
		return false
	}
	return ok
}

func verifyAnchor(rep *Report, cp ledger.Checkpoint, opt Options) AnchorResult {
	ar := AnchorResult{CheckpointID: cp.ID, Status: cp.AnchorStatus}
	sev := "warning"
	if opt.RequireAnchors {
		sev = "error"
	}
	if cp.ExternalAnchorProof == nil || *cp.ExternalAnchorProof == "" {
		if cp.AnchorStatus == "anchored" {
			rep.add("error", "anchor_missing", cp.FirstSeq, "", cp.ID, "checkpoint marked anchored but proof is missing")
			ar.Status = "missing"
		} else {
			rep.add(sev, "anchor_not_available", cp.FirstSeq, "", cp.ID, "checkpoint has no external anchor yet (status %s)", cp.AnchorStatus)
		}
		return ar
	}
	res, err := anchor.Verify(*cp.ExternalAnchorProof, []byte(cp.Statement), opt.TSARoots)
	if err != nil {
		rep.add("error", "anchor_invalid", cp.FirstSeq, "", cp.ID, "external anchor does not verify: %v", err)
		ar.Status = "failed"
		return ar
	}
	ar.Status, ar.Authority, ar.Time, ar.ChainTrust = "verified", res.Authority, res.Time.UTC().Format("2006-01-02T15:04:05Z"), res.ChainTrust
	return ar
}
