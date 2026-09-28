package export

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"

	"audittrail.dev/packages/ingestion-go/internal/ledger"
	"audittrail.dev/packages/ingestion-go/internal/verify"
)

// MaxPDFEvents caps the event table; the CSV and bundle carry every row.
const MaxPDFEvents = 2000

type pdfDoc struct {
	*fpdf.Fpdf
	tr func(string) string
}

func (p *pdfDoc) h1(s string) {
	p.SetFont("Helvetica", "B", 15)
	p.SetTextColor(20, 30, 60)
	p.CellFormat(0, 9, p.tr(s), "", 1, "L", false, 0, "")
	p.SetTextColor(0, 0, 0)
}

func (p *pdfDoc) h2(s string) {
	p.Ln(3)
	p.SetFont("Helvetica", "B", 11.5)
	p.SetTextColor(20, 30, 60)
	p.CellFormat(0, 7, p.tr(s), "B", 1, "L", false, 0, "")
	p.SetTextColor(0, 0, 0)
	p.Ln(1.5)
}

func (p *pdfDoc) para(s string) {
	p.SetFont("Helvetica", "", 9)
	p.MultiCell(0, 4.6, p.tr(s), "", "L", false)
	p.Ln(1)
}

func (p *pdfDoc) kv(k, v string) {
	p.SetFont("Helvetica", "B", 9)
	p.CellFormat(55, 5, p.tr(k), "", 0, "L", false, 0, "")
	p.SetFont("Helvetica", "", 9)
	p.MultiCell(0, 5, p.tr(v), "", "L", false)
}

// wrapLines counts the lines MultiCell will produce for an already
// cp1252-translated string. fpdf's SplitText expects UTF-8 and cannot be
// used on translated text, so this mirrors MultiCell's byte-wise wrapping.
func (p *pdfDoc) wrapLines(txt string, w float64) []string {
	wmax := w - 2*p.GetCellMargin()
	var lines []string
	b := []byte(strings.TrimRight(txt, "\n"))
	sep, i, j := -1, 0, 0
	l := 0.0
	for i < len(b) {
		c := b[i]
		if c == '\n' {
			lines = append(lines, string(b[j:i]))
			i++
			sep, j, l = -1, i, 0
			continue
		}
		if c == ' ' {
			sep = i
		}
		l += p.GetStringWidth(string([]byte{c}))
		if l > wmax {
			if sep == -1 {
				if i == j {
					i++
				}
				lines = append(lines, string(b[j:i]))
			} else {
				lines = append(lines, string(b[j:sep]))
				i = sep + 1
			}
			sep, j, l = -1, i, 0
		} else {
			i++
		}
	}
	if i != j || len(lines) == 0 {
		lines = append(lines, string(b[j:i]))
	}
	return lines
}

// table draws rows with wrapped cells; header repeats on page breaks.
func (p *pdfDoc) table(widths []float64, head []string, rows [][]string, fontSize float64, shade func(i int) bool) {
	lh := fontSize * 0.45
	drawHead := func() {
		p.SetFont("Helvetica", "B", fontSize)
		p.SetFillColor(225, 230, 242)
		hh := 0.0
		for i, h := range head {
			hh = max(hh, float64(len(p.wrapLines(p.tr(h), widths[i]-1.4)))*lh+1.5)
		}
		x, y := p.GetX(), p.GetY()
		for i, h := range head {
			p.Rect(x, y, widths[i], hh, "FD")
			p.SetXY(x+0.7, y+0.7)
			p.MultiCell(widths[i]-1.4, lh, p.tr(h), "", "L", false)
			x += widths[i]
		}
		left, _, _, _ := p.GetMargins()
		p.SetXY(left, y+hh)
	}
	_, pageH := p.GetPageSize()
	_, _, _, bottom := p.GetMargins()
	drawHead()
	p.SetFont("Helvetica", "", fontSize)
	for ri, r := range rows {
		rh := 0.0
		for i, c := range r {
			rh = max(rh, float64(len(p.wrapLines(p.tr(c), widths[i]-1.4)))*lh+1.5)
		}
		if p.GetY()+rh > pageH-bottom-8 {
			p.AddPage()
			drawHead()
			p.SetFont("Helvetica", "", fontSize)
		}
		x, y := p.GetX(), p.GetY()
		fill := "D"
		if shade != nil && shade(ri) {
			p.SetFillColor(253, 236, 234)
			fill = "FD"
		}
		for i, c := range r {
			p.Rect(x, y, widths[i], rh, fill)
			p.SetXY(x+0.7, y+0.7)
			p.MultiCell(widths[i]-1.4, lh, p.tr(c), "", "L", false)
			x += widths[i]
		}
		left, _, _, _ := p.GetMargins()
		p.SetXY(left, y+rh)
	}
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func deref(p *string, def string) string {
	if p == nil || *p == "" {
		return def
	}
	return *p
}

// WritePDF renders the human-readable compliance evidence report (Task 6.2).
func WritePDF(w io.Writer, b verify.Bundle, t Template, rep verify.Report) error {
	f := fpdf.New("L", "mm", "A4", "")
	p := &pdfDoc{Fpdf: f, tr: f.UnicodeTranslatorFromDescriptor("")}
	p.SetMargins(12, 12, 12)
	p.SetAutoPageBreak(true, 14)
	p.AliasNbPages("")
	generated := time.Now().UTC().Format("2006-01-02 15:04 UTC")
	p.SetFooterFunc(func() {
		p.SetY(-10)
		p.SetFont("Helvetica", "", 7)
		p.SetTextColor(110, 110, 110)
		p.CellFormat(0, 4, p.tr(fmt.Sprintf("AuditTrail evidence export - %s - tenant %s - generated %s - evidence mapping, not legal advice - page %d/{nb}",
			t.ID, b.Tenant.ID, generated, p.PageNo())), "", 0, "C", false, 0, "")
		p.SetTextColor(0, 0, 0)
	})

	// ---- cover ----------------------------------------------------------------
	p.AddPage()
	p.SetFont("Helvetica", "", 9)
	p.SetTextColor(90, 90, 90)
	p.CellFormat(0, 5, p.tr("COMPLIANCE EVIDENCE REPORT"), "", 1, "L", false, 0, "")
	p.SetTextColor(0, 0, 0)
	p.h1(t.Title)
	p.para(t.Source + ". " + t.Summary)

	first, last := "-", "-"
	if n := len(b.Events); n > 0 {
		first, last = b.Events[0].Timestamp, b.Events[n-1].Timestamp
	}
	p.h2("Scope")
	p.kv("Tenant", fmt.Sprintf("%s (%s)", b.Tenant.Name, b.Tenant.ID))
	p.kv("Records in this export", fmt.Sprintf("%d (seq %d to %d)", len(b.Events), rep.FirstSeq, rep.LastSeq))
	p.kv("Period covered", first+"  to  "+last)
	p.kv("Checkpoints covering the rows", fmt.Sprint(len(b.Checkpoints)))
	p.kv("Generated", generated)

	p.h2("Integrity verification (recomputed while generating this report)")
	status := "PASSED: every record's hash, chain link and signature verified"
	if !rep.OK {
		status = fmt.Sprintf("FAILED: %d issue(s); tampered or missing records at seq %v", len(rep.Issues), rep.TamperedSeqs)
		p.SetTextColor(170, 20, 20)
	} else {
		p.SetTextColor(20, 120, 50)
	}
	p.SetFont("Helvetica", "B", 10.5)
	p.MultiCell(0, 6, p.tr(status), "", "L", false)
	p.SetTextColor(0, 0, 0)
	p.kv("Hashes recomputed", fmt.Sprintf("%d of %d records (SHA-256 over RFC 8785 canonical JSON)", rep.EventsChecked, len(b.Events)))
	p.kv("Ed25519 signatures valid", fmt.Sprintf("%d of %d", rep.SignaturesVerified, len(b.Events)))
	p.kv("Chain starts at", rep.ChainStart)
	p.kv("Head hash", rep.HeadHash)
	anchored := 0
	var auth []string
	for _, a := range rep.Anchors {
		if a.Status == "verified" {
			anchored++
			auth = append(auth, a.Authority)
		}
	}
	sort.Strings(auth)
	auth = uniq(auth)
	p.kv("External RFC 3161 anchors", fmt.Sprintf("%d of %d checkpoints anchored and verified (%s)", anchored, len(rep.Anchors), strings.Join(auth, ", ")))
	for _, is := range rep.Issues {
		if is.Severity == "error" {
			p.kv("  ! "+is.Kind, fmt.Sprintf("seq %d: %s", is.Seq, is.Detail))
		}
	}
	p.para("To verify independently, without trusting AuditTrail, run `audittrail-verify <bundle.json>` on the JSON evidence bundle exported with this report. It recomputes every hash, link, signature and Merkle root, and validates each RFC 3161 time-stamp token against the issuing authority's certificate.")

	// ---- clause mapping -----------------------------------------------------------
	p.AddPage()
	p.h1("How each clause is evidenced")
	var rows [][]string
	for _, c := range t.Clauses {
		var fields []string
		for _, fm := range t.Fields {
			for _, ref := range fm.Clauses {
				if ref == c.Ref {
					fields = append(fields, fm.Label)
				}
			}
		}
		if strings.Contains(c.Ref, "19(1)") || strings.HasPrefix(c.Ref, "AU-11") {
			fields = append(fields, "tenant retention_days / legal_hold")
		}
		rows = append(rows, []string{c.Ref + "\n" + c.Title, c.Requirement, c.Evidence, strings.Join(fields, ", ")})
	}
	p.table([]float64{38, 80, 100, 55}, []string{"Clause", "Requirement (paraphrased)", "How this export evidences it", "Fields in this export"}, rows, 7.8, nil)

	p.h2("Field to clause mapping (use this to match each column of the event log / CSV)")
	rows = nil
	for _, fm := range t.Fields {
		rows = append(rows, []string{fm.Label, strings.Join(fm.Clauses, "; "), fm.Rationale})
	}
	p.table([]float64{50, 55, 168}, []string{"Field", "Evidences clause(s)", "Why"}, rows, 7.8, nil)

	// ---- retention -------------------------------------------------------------------
	p.h2("Retention and legal hold (" + t.RetentionClause + ")")
	ok := "meets"
	if b.Tenant.RetentionDays < t.MinRetentionDays {
		ok = "DOES NOT MEET"
	}
	p.kv("Configured retention", fmt.Sprintf("%d days: %s the %d-day minimum for this template", b.Tenant.RetentionDays, ok, t.MinRetentionDays))
	hold := "not active"
	if b.Tenant.LegalHold {
		hold = "ACTIVE: all purges are blocked regardless of retention"
	}
	p.kv("Legal hold", hold)
	p.para("Enforcement: the database refuses retention below 183 days, and the application role has no DELETE privilege on the ledger. The only purge path is a database function that raises an error while a legal hold is active, and that deletes only whole checkpoint ranges which are already externally anchored. The chain therefore stays verifiable from the checkpoint's signed head hash.")

	// ---- checkpoints -----------------------------------------------------------------
	p.AddPage()
	p.h1("Checkpoints and external anchors")
	p.para("Each checkpoint is an Ed25519-signed statement holding the RFC 6962 Merkle root of a contiguous run of records. SHA-256 of the statement was time-stamped by an independent RFC 3161 Time-Stamp Authority, which proves the records existed in exactly this form at the anchor time.")
	rows = nil
	anchorByID := map[string]verify.AnchorResult{}
	for _, a := range rep.Anchors {
		anchorByID[a.CheckpointID] = a
	}
	for _, cp := range b.Checkpoints {
		a := anchorByID[cp.ID]
		v := a.Status
		if a.Time != "" {
			v += " @ " + a.Time
		}
		rows = append(rows, []string{cp.ID, fmt.Sprintf("%d - %d (%d)", cp.FirstSeq, cp.LastSeq, cp.RowCount), cp.MerkleRoot, cp.KeyID,
			deref(cp.AnchorAuthority, "-"), v})
	}
	if len(rows) == 0 {
		p.para("No checkpoints cover these records yet: the checkpoint worker has not run since they were written.")
	} else {
		p.table([]float64{42, 30, 72, 38, 55, 36}, []string{"Checkpoint", "Seq range (rows)", "Merkle root", "Signing key", "Anchor authority", "Anchor verified"}, rows, 7, nil)
	}
	if len(b.Checkpoints) > 0 {
		cp := b.Checkpoints[len(b.Checkpoints)-1]
		sum := sha256.Sum256([]byte(cp.Statement))
		p.h2("Example anchor proof (latest checkpoint)")
		p.kv("Signed statement", cp.Statement)
		p.kv("SHA-256(statement)", hex.EncodeToString(sum[:])+"  (the RFC 3161 message imprint)")
		p.kv("Statement signature", cp.Signature)
		if cp.ExternalAnchorProof != nil {
			p.kv("TimeStampToken (base64, excerpt)", trunc(*cp.ExternalAnchorProof, 300))
		}
	}

	// ---- event log --------------------------------------------------------------------
	p.AddPage()
	p.h1("Event log")
	hi := map[string]bool{}
	for _, o := range t.HighlightOutcome {
		hi[o] = true
	}
	lbl := func(field, name string) string {
		if c := t.ClausesFor(field); len(c) > 0 {
			return name + "\n[" + strings.Join(c, "; ") + "]"
		}
		return name
	}
	evs := b.Events
	note := ""
	if len(evs) > MaxPDFEvents {
		evs = evs[len(evs)-MaxPDFEvents:]
		note = fmt.Sprintf(" Showing the latest %d of %d records; the CSV and JSON bundle contain all of them.", MaxPDFEvents, len(b.Events))
	}
	p.para("Column headers name the clause each column evidences. Rows with outcome " + strings.Join(t.HighlightOutcome, "/") + " are shaded." + note)
	tampered := map[int64]bool{}
	for _, s := range rep.TamperedSeqs {
		tampered[s] = true
	}
	rows = nil
	for _, e := range evs {
		model := deref(e.ModelID, "-")
		if e.ModelVersion != nil && *e.ModelVersion != "" && *e.ModelVersion != "unknown" {
			model += "@" + *e.ModelVersion
		}
		integ := trunc(e.Hash, 14)
		if tampered[e.Seq] {
			integ = "TAMPERED " + integ
		}
		rows = append(rows, []string{fmt.Sprint(e.Seq), e.Timestamp, trunc(deref(e.HumanPrincipalID, "(autonomous)"), 34), trunc(e.AgentID, 30),
			trunc(model, 26), trunc(e.Action, 30), trunc(e.TargetResource, 60), e.Outcome, integ})
	}
	p.table([]float64{11, 35, 33, 30, 25, 29, 56, 18, 36}, []string{"seq", lbl("timestamp", "timestamp"), lbl("human_principal_id", "principal"),
		lbl("agent_id", "agent"), lbl("model_id", "model"), lbl("action", "action"), lbl("target_resource", "target_resource"),
		lbl("outcome", "outcome"), lbl("hash", "hash")}, rows, 6.4, func(i int) bool { return hi[evs[i].Outcome] })

	// ---- anomalies ----------------------------------------------------------------------
	var anomalies []ledger.Record
	for _, e := range b.Events {
		if hi[e.Outcome] {
			anomalies = append(anomalies, e)
		}
	}
	p.h2(fmt.Sprintf("Anomalies: %d %s records", len(anomalies), strings.Join(t.HighlightOutcome, "/")))
	if len(anomalies) == 0 {
		p.para("None in this period.")
	} else {
		rows = nil
		for i, e := range anomalies {
			if i >= 300 {
				break
			}
			detail := anomalyDetail(e.Metadata)
			rows = append(rows, []string{fmt.Sprint(e.Seq), e.Timestamp, e.Outcome, trunc(e.AgentID, 28), trunc(e.TargetResource, 50), detail})
		}
		p.table([]float64{11, 35, 16, 32, 60, 119}, []string{"seq", "timestamp", "outcome", "agent", "target", "why (policy rule / error / human decision)"}, rows, 6.4, nil)
	}
	return p.Output(w)
}

func uniq(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// anomalyDetail surfaces why an action was denied or failed.
func anomalyDetail(md json.RawMessage) string {
	var m map[string]any
	if len(md) == 0 || json.Unmarshal(md, &m) != nil {
		return ""
	}
	var parts []string
	if pol, ok := m["policy"].(map[string]any); ok {
		parts = append(parts, fmt.Sprintf("blocked by policy rule %v", pol["rule"]))
	}
	if e, ok := m["error"].(map[string]any); ok {
		parts = append(parts, fmt.Sprintf("error %v: %v", e["code"], e["message"]))
	} else if e, ok := m["error"].(string); ok {
		parts = append(parts, "error: "+e)
	}
	if te, ok := m["tool_error"].(string); ok && te != "" {
		parts = append(parts, "tool error: "+te)
	}
	if a, ok := m["elicitation_action"].(string); ok {
		parts = append(parts, "human "+a+"d the request")
	}
	if c, ok := m["cancelled"].(bool); ok && c {
		parts = append(parts, "cancelled by the agent")
	}
	if n, ok := m["no_response"].(bool); ok && n {
		parts = append(parts, fmt.Sprintf("no response (%v)", m["reason"]))
	}
	if st, ok := m["status"].(float64); ok {
		parts = append(parts, fmt.Sprintf("HTTP status %d", int(st)))
	}
	if len(parts) == 0 {
		return trunc(string(md), 160)
	}
	return trunc(strings.Join(parts, "; "), 240)
}
