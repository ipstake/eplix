package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/verify"
	backend "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// gen holds the keys and CAs of one run. All are made fresh, so every run writes new
// documents with the same verdicts.
type gen struct {
	now          time.Time
	ca, otherCA  *testCA
	k1, k2, weak *rsa.PrivateKey
}

func newGen(now time.Time) *gen {
	return &gen{
		now:     now,
		ca:      newCA("Eplix test CA", now),
		otherCA: newCA("Eplix other test CA", now),
		k1:      must(rsa.GenerateKey(rand.Reader, 2048)),
		k2:      must(rsa.GenerateKey(rand.Reader, 2048)),
		weak:    must(rsa.GenerateKey(rand.Reader, 1024)),
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwk is an RSA key of a key set (RFC 7517) in the n and e form.
func jwk(kid string, k *rsa.PrivateKey) json.RawMessage {
	return obj("alg", "RS256", "e", b64(big.NewInt(int64(k.E)).Bytes()), "kid", kid, "kty", "RSA", "n", b64(k.N.Bytes()), "use", "sig")
}

func jwks(keys ...json.RawMessage) json.RawMessage {
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = string(k)
	}
	return raw(`{"keys":[` + strings.Join(parts, ",") + `]}`)
}

func header(kid string) []byte { return obj("alg", "RS256", "kid", kid, "typ", "JWT") }

// sign makes a compact JWS (RS256) over header and payload as given.
func sign(k *rsa.PrivateKey, header, payload []byte) string {
	signed := b64(header) + "." + b64(payload)
	h := sha256.Sum256([]byte(signed))
	sig := must(rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:]))
	return signed + "." + b64(sig)
}

// tokSpec changes a good token. Zero fields keep it: header RS256 with kid k1, key k1.
type tokSpec struct {
	claims  func(c map[string]any)
	payload func(p []byte) []byte
	header  []byte
	key     *rsa.PrivateKey
	token   func(t string) string
	// after changes the identity after the document bound it.
	after func(id *backend.Identity)
}

func (g *gen) jwt(c map[string]any, s tokSpec) string {
	if s.claims != nil {
		s.claims(c)
	}
	p := must(json.Marshal(c))
	if s.payload != nil {
		p = s.payload(p)
	}
	h := s.header
	if h == nil {
		h = header("k1")
	}
	k := s.key
	if k == nil {
		k = g.k1
	}
	t := sign(k, h, p)
	if s.token != nil {
		t = s.token(t)
	}
	return t
}

// setPath sets a claim; a dotted path walks nested objects. A nil value deletes it.
func setPath(c map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		c = c[p].(map[string]any)
	}
	if v == nil {
		delete(c, parts[len(parts)-1])
		return
	}
	c[parts[len(parts)-1]] = v
}

func set(path string, v any) func(c map[string]any) {
	return func(c map[string]any) { setPath(c, path, v) }
}

func del(path string) func(c map[string]any) { return set(path, nil) }

// identity is a runner identity with fixed keys and the given setup state, not yet bound.
func identity(state backend.SetupState) *backend.Identity {
	return &backend.Identity{State: state, ImportKEM: 0x0020, ImportKDF: 0x0001, ImportAEAD: 0x0003,
		ImportKey: sum256("import key"), TLSKeyHash: sum256("tls key")}
}

func encode(id *backend.Identity) []byte { return must(wire.EncodeIdentity(id)) }

// bound returns an identity whose attestation carries the user data for nonce and the document
// that doc makes from it.
func bound(state backend.SetupState, nonce []byte, platform, format string, doc func(ud []byte) []byte) *backend.Identity {
	id := identity(state)
	ud := backend.IdentityUserData(nonce, id)
	id.Attestation = &backend.Attestation{Platform: platform, Format: format, UserData: ud, Document: doc(ud)}
	return id
}

func (g *gen) cloud(platform, format string, state backend.SetupState, nonce []byte, claims func(ud []byte) map[string]any, s tokSpec) []byte {
	id := bound(state, nonce, platform, format, func(ud []byte) []byte { return []byte(g.jwt(claims(ud), s)) })
	if s.after != nil {
		s.after(id)
	}
	return encode(id)
}

// keyServer answers the key set fetches of the verifiers: the OpenID discovery document of
// whatever issuer is asked, naming /certs on the same host, and the case's key set there.
type keyServer json.RawMessage

func (k keyServer) RoundTrip(r *http.Request) (*http.Response, error) {
	base := "https://" + r.URL.Host
	status, body := http.StatusNotFound, []byte("not found")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		status, body = http.StatusOK, obj("issuer", base, "jwks_uri", base+"/certs")
	case "/certs":
		if k != nil {
			status, body = http.StatusOK, []byte(k)
		}
	}
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)), Request: r}, nil
}

// identityVerdict runs what a signing client runs on an IDENTITY answer: the settings build a
// verifier, the answer decodes, its user data is the hash of its fields and the nonce, and the
// verifier accepts it.
func identityVerdict(att, keys json.RawMessage, nonce, idb []byte) error {
	var a verify.Attestation
	if err := json.Unmarshal(att, &a); err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	v, err := a.NewVerifier(verify.WithHTTPClient(&http.Client{Transport: keyServer(keys), Timeout: 5 * time.Second}))
	if err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	id, err := wire.DecodeIdentity(idb)
	if err != nil {
		return err
	}
	if id.Attestation == nil || !bytes.Equal(id.Attestation.UserData, backend.IdentityUserData(nonce, id)) {
		return errors.New("oracle: attestation user data is not backend.IdentityUserData(nonce, identity)")
	}
	return v(context.Background(), nonce, id)
}

func (g *gen) idCase(name string, att, keys json.RawMessage, issuer string, nonce, idb []byte) identityCase {
	c := identityCase{Name: name, Attestation: att, JWKS: keys, Issuer: issuer, Nonce: hex.EncodeToString(nonce),
		Identity: hex.EncodeToString(idb), Now: g.now.Unix()}
	c.Expect, c.Error = verdict(identityVerdict(att, keys, nonce, idb))
	return c
}
