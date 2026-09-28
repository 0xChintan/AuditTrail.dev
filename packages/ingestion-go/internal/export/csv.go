package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"audittrail.dev/packages/ingestion-go/internal/ledger"
	"audittrail.dev/packages/ingestion-go/internal/verify"
)

// csvSafe neutralizes spreadsheet formula injection.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func header(t Template, field, label string) string {
	if cl := t.ClausesFor(field); len(cl) > 0 {
		return fmt.Sprintf("%s [%s]", label, strings.Join(cl, "; "))
	}
	return label
}

// WriteCSV writes one row per event. Every column header names the clauses
// that column evidences, e.g. "timestamp [AU-3(b)]". Each row also carries
// its covering checkpoint and that checkpoint's external anchor.
func WriteCSV(w io.Writer, b verify.Bundle, t Template, rep verify.Report) error {
	cw := csv.NewWriter(w)
	// Each column lists the template fields it evidences, most specific first;
	// the header shows the clauses of the first one the template maps.
	cols := []struct {
		label string
		keys  []string
	}{
		{"seq", []string{"seq", "hash"}}, {"timestamp", []string{"timestamp"}},
		{"human_principal_id", []string{"human_principal_id"}}, {"agent_id", []string{"agent_id"}},
		{"model_id", []string{"model_id"}}, {"model_version", []string{"model_version", "model_id"}},
		{"delegation_chain", []string{"delegation_chain"}}, {"action", []string{"action"}},
		{"target_resource", []string{"target_resource"}}, {"outcome", []string{"outcome"}},
		{"metadata", []string{"metadata"}}, {"previous_hash", []string{"previous_hash", "hash"}},
		{"hash", []string{"hash"}}, {"signature", []string{"signature"}}, {"key_id", []string{"key_id", "signature"}},
	}
	head := []string{"event_id"}
	for _, c := range cols {
		h := c.label
		for _, k := range c.keys {
			if t.ClausesFor(k) != nil {
				h = header(t, k, c.label)
				break
			}
		}
		head = append(head, h)
	}
	cpHead := header(t, "checkpoint", "checkpoint")
	head = append(head, "integrity_check", cpHead+" id", "checkpoint_merkle_root", "anchor_status", "anchor_authority", "anchored_at")
	if err := cw.Write(head); err != nil {
		return err
	}

	tampered := map[int64]bool{}
	for _, s := range rep.TamperedSeqs {
		tampered[s] = true
	}
	covering := func(seq int64) *ledger.Checkpoint {
		for i := range b.Checkpoints {
			if b.Checkpoints[i].FirstSeq <= seq && seq <= b.Checkpoints[i].LastSeq {
				return &b.Checkpoints[i]
			}
		}
		return nil
	}
	js := func(v json.RawMessage) string {
		if len(v) == 0 {
			return ""
		}
		return string(v)
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	for _, e := range b.Events {
		integrity := "verified"
		if tampered[e.Seq] {
			integrity = "FAILED"
		}
		row := []string{e.ID, fmt.Sprint(e.Seq), e.Timestamp, str(e.HumanPrincipalID), e.AgentID, str(e.ModelID), str(e.ModelVersion),
			js(e.DelegationChain), e.Action, e.TargetResource, e.Outcome, js(e.Metadata), e.PreviousHash, e.Hash, e.Signature, e.KeyID, integrity}
		if cp := covering(e.Seq); cp != nil {
			row = append(row, cp.ID, cp.MerkleRoot, cp.AnchorStatus, str(cp.AnchorAuthority), str(cp.AnchoredAt))
		} else {
			row = append(row, "", "", "not yet checkpointed", "", "")
		}
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
