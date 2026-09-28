// Package pii implements per-subject envelope encryption for crypto-shredding
// (v2 phase 5). See schemas/v2/SPEC.md §4 and THREAT_MODEL.md for the legal
// caveat: shredding makes the ciphertext undecryptable, which may or may not
// satisfy "erasure" in a given jurisdiction.
package pii

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"audittrail.dev/packages/ingestion-go/internal/contract"
	"audittrail.dev/packages/ingestion-go/internal/keys"
)

var ErrErased = errors.New("subject key destroyed: data has been crypto-shredded")

type Encrypter struct {
	KEK *keys.MasterKey
}

func aad(tenantID, subject, dekID string) string {
	return "dek|" + tenantID + "|" + subject + "|" + dekID
}

func fieldAAD(tenantID, subject, field, eventID string) []byte {
	return []byte(tenantID + "|" + subject + "|" + field + "|" + eventID)
}

// SubjectDigest identifies a subject in erasure records without repeating it.
func SubjectDigest(tenantID, subject string) string {
	s := sha256.Sum256([]byte(tenantID + "|" + subject))
	return hex.EncodeToString(s[:])
}

// liveDEK returns the live DEK for a subject, creating one if needed.
func (e *Encrypter) liveDEK(ctx context.Context, tx pgx.Tx, tenantID, subject string) (string, []byte, error) {
	var dekID, wrapped string
	err := tx.QueryRow(ctx, `SELECT dek_id, wrapped_dek FROM subject_keys WHERE tenant_id=$1 AND subject=$2 AND destroyed_at IS NULL`, tenantID, subject).Scan(&dekID, &wrapped)
	if errors.Is(err, pgx.ErrNoRows) {
		dek := make([]byte, 32)
		if _, err := rand.Read(dek); err != nil {
			return "", nil, err
		}
		idb := make([]byte, 12)
		rand.Read(idb)
		dekID = "dek_" + hex.EncodeToString(idb)
		wrapped = e.KEK.Seal(dek, aad(tenantID, subject, dekID))
		ct, err := tx.Exec(ctx, `INSERT INTO subject_keys (dek_id, tenant_id, subject, wrapped_dek) VALUES ($1,$2,$3,$4)
			ON CONFLICT (tenant_id, subject) WHERE destroyed_at IS NULL DO NOTHING`, dekID, tenantID, subject, wrapped)
		if err != nil {
			return "", nil, err
		}
		if ct.RowsAffected() == 0 { // concurrent creator won: use theirs
			return e.liveDEK(ctx, tx, tenantID, subject)
		}
		return dekID, dek, nil
	}
	if err != nil {
		return "", nil, err
	}
	dek, err := e.KEK.Open(wrapped, aad(tenantID, subject, dekID))
	return dekID, dek, err
}

// Encrypt implements sequencer.PIIEncrypter.
func (e *Encrypter) Encrypt(ctx context.Context, tx pgx.Tx, tenantID, eventID string, p *contract.PII) (*contract.Value, error) {
	dekID, dek, err := e.liveDEK(ctx, tx, tenantID, p.Subject)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	fields := &contract.Value{Kind: contract.Object}
	for _, f := range p.Fields {
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		ct := gcm.Seal(nil, nonce, []byte(f.Value.S), fieldAAD(tenantID, p.Subject, f.Key, eventID))
		fields.O = append(fields.O, contract.M(f.Key, contract.Obj(
			contract.M("n", contract.Str(base64.StdEncoding.EncodeToString(nonce))),
			contract.M("c", contract.Str(base64.StdEncoding.EncodeToString(ct))))))
	}
	return contract.Obj(contract.M("subject", contract.Str(p.Subject)), contract.M("kid", contract.Str(dekID)), contract.M("fields", fields)), nil
}

// Decrypt returns the plaintext fields of a stored pii_ct object.
func (e *Encrypter) Decrypt(ctx context.Context, tx pgx.Tx, tenantID, eventID string, piiCT []byte) (map[string]string, error) {
	v, perr := contract.Parse(piiCT)
	if perr != nil {
		return nil, errors.New(perr.Error())
	}
	sub, _ := v.Get("subject")
	kid, _ := v.Get("kid")
	fields, _ := v.Get("fields")
	if sub == nil || kid == nil || fields == nil {
		return nil, errors.New("malformed pii_ct")
	}
	var wrapped *string
	if err := tx.QueryRow(ctx, `SELECT wrapped_dek FROM subject_keys WHERE tenant_id=$1 AND dek_id=$2`, tenantID, kid.S).Scan(&wrapped); err != nil {
		return nil, fmt.Errorf("dek lookup: %w", err)
	}
	if wrapped == nil {
		return nil, ErrErased
	}
	dek, err := e.KEK.Open(*wrapped, aad(tenantID, sub.S, kid.S))
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	out := map[string]string{}
	for _, m := range fields.O {
		n, _ := m.Value.Get("n")
		c, _ := m.Value.Get("c")
		nonce, _ := base64.StdEncoding.DecodeString(n.S)
		ct, _ := base64.StdEncoding.DecodeString(c.S)
		pt, err := gcm.Open(nil, nonce, ct, fieldAAD(tenantID, sub.S, m.Key, eventID))
		if err != nil {
			return nil, fmt.Errorf("field %s: decryption failed", m.Key)
		}
		out[m.Key] = string(pt)
	}
	return out, nil
}

// Erase destroys every live and historical DEK of a subject. Returns the
// destroyed key ids.
func Erase(ctx context.Context, tx pgx.Tx, tenantID, subject, reason string) ([]string, error) {
	rows, err := tx.Query(ctx, `UPDATE subject_keys SET wrapped_dek=NULL, destroyed_at=NOW(), destroyed_reason=$3
		WHERE tenant_id=$1 AND subject=$2 AND destroyed_at IS NULL RETURNING dek_id`, tenantID, subject, reason)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
