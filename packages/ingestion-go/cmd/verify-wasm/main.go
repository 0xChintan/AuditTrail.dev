//go:build js && wasm

// Command verify-wasm exposes the offline v2 verifier to JavaScript:
//
//	const reportJSON = auditTrailVerify(bundleJSON, optionsJSON)
//
// optionsJSON: {"log_keys":[vkey],"witnesses":[vkey],"quorum":2,"max_age_seconds":86400,"now":"RFC3339"}
// It performs no I/O: everything is computed from the arguments.
package main

import (
	"encoding/json"
	"syscall/js"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/verify2"
)

type opts struct {
	LogKeys        []string `json:"log_keys"`
	Witnesses      []string `json:"witnesses"`
	Quorum         int      `json:"quorum"`
	MaxAgeSeconds  int64    `json:"max_age_seconds"`
	Now            string   `json:"now"`
	RequireCovered bool     `json:"require_covered"`
	RequireAnchor  bool     `json:"require_anchor"`
	Others         []string `json:"others"` // other bundle JSONs (split-view detection)
}

func verify(_ js.Value, args []js.Value) any {
	fail := func(msg string) any {
		b, _ := json.Marshal(map[string]any{"ok": false, "error": msg})
		return string(b)
	}
	if len(args) < 1 {
		return fail("usage: auditTrailVerify(bundleJSON, optionsJSON)")
	}
	var b verify2.Bundle
	if err := json.Unmarshal([]byte(args[0].String()), &b); err != nil {
		return fail("bundle is not valid JSON: " + err.Error())
	}
	var o opts
	if len(args) > 1 && args[1].Type() == js.TypeString && args[1].String() != "" {
		if err := json.Unmarshal([]byte(args[1].String()), &o); err != nil {
			return fail("options are not valid JSON: " + err.Error())
		}
	}
	vo := verify2.Options{LogKeys: o.LogKeys, Witnesses: o.Witnesses, Quorum: o.Quorum,
		MaxAge: time.Duration(o.MaxAgeSeconds) * time.Second, RequireCovered: o.RequireCovered, RequireAnchor: o.RequireAnchor, Now: time.Now()}
	if o.Now != "" {
		if t, err := time.Parse(time.RFC3339, o.Now); err == nil {
			vo.Now = t
		}
	}
	for _, s := range o.Others {
		var ob verify2.Bundle
		if json.Unmarshal([]byte(s), &ob) == nil {
			vo.Others = append(vo.Others, &ob)
		}
	}
	out, _ := json.Marshal(verify2.Verify(&b, vo))
	return string(out)
}

func main() {
	js.Global().Set("auditTrailVerify", js.FuncOf(verify))
	js.Global().Set("auditTrailVerifierReady", true)
	select {}
}
