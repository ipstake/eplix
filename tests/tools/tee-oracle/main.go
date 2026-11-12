// Command tee-oracle writes tests/fixtures/tee/oracle-vectors.json: the verdicts of the Go
// attestation verifiers of tee-signer (module attestation-verify) on synthetic settings,
// runner identities and AWS Nitro documents. TeeVerifierTests.fs replays every case through
// Eplix's verifiers and fails on any verdict that differs. Every key, certificate, token and
// document here is made at run time; nothing comes from a real cloud. gen.sh builds and runs it
// against a tee-signer checkout.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

type settingsCase struct {
	Name        string          `json:"name"`
	Attestation json.RawMessage `json:"attestation"`
	Valid       bool            `json:"valid"`
	Error       string          `json:"error"`
}

type identityCase struct {
	Name        string          `json:"name"`
	Attestation json.RawMessage `json:"attestation"`
	JWKS        json.RawMessage `json:"jwks"`
	Issuer      string          `json:"issuer"`
	Nonce       string          `json:"nonce"`
	Identity    string          `json:"identity"`
	Now         int64           `json:"now"`
	Expect      string          `json:"expect"`
	Error       string          `json:"error"`
}

type nitroCase struct {
	Name     string            `json:"name"`
	Document string            `json:"document"`
	RootsPEM []string          `json:"roots_pem"`
	PCRs     map[string]string `json:"pcrs"`
	Nonce    *string           `json:"nonce"`
	UserData *string           `json:"user_data"`
	NowMs    int64             `json:"now_ms"`
	Expect   string            `json:"expect"`
	Error    string            `json:"error"`
}

type output struct {
	GeneratedAt   int64          `json:"generated_at"`
	Source        string         `json:"source"`
	Note          string         `json:"note"`
	SettingsCases []settingsCase `json:"settings_cases"`
	IdentityCases []identityCase `json:"identity_cases"`
	NitroCases    []nitroCase    `json:"nitro_cases"`
}

const note = "Verdicts of the tee-signer Go attestation verifiers (runnerclient/verify for settings and " +
	"identities, attest.VerifyNitro for Nitro documents) on synthetic inputs only: throwaway RSA keys " +
	"for the MAA and Confidential Space tokens, a local P-384 test CA for the Nitro documents. " +
	"Regenerate with tests/tools/tee-oracle/gen.sh."

func main() {
	out := flag.String("out", "oracle-vectors.json", "output file")
	source := flag.String("source", "tee-signer attestation-verify", "what the verdicts come from, for the file's source field")
	flag.Parse()

	g := newGen(time.Now().Truncate(time.Second))
	o := output{
		GeneratedAt:   g.now.Unix(),
		Source:        *source,
		Note:          note,
		SettingsCases: settingsCases(),
		IdentityCases: g.identityCases(),
		NitroCases:    g.nitroCases(),
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(o); err != nil {
		fail(err)
	}
	if err := os.WriteFile(*out, buf.Bytes(), 0o644); err != nil {
		fail(err)
	}
	count := func(ok int, all int) string { return fmt.Sprintf("%d (%d accepted)", all, ok) }
	s, i, n := 0, 0, 0
	for _, c := range o.SettingsCases {
		if c.Valid {
			s++
		}
	}
	for _, c := range o.IdentityCases {
		if c.Expect == "ok" {
			i++
		}
	}
	for _, c := range o.NitroCases {
		if c.Expect == "ok" {
			n++
		}
	}
	fmt.Printf("settings %s, identity %s, nitro %s\n", count(s, len(o.SettingsCases)), count(i, len(o.IdentityCases)), count(n, len(o.NitroCases)))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "tee-oracle:", err)
	os.Exit(1)
}

func must[T any](v T, err error) T {
	if err != nil {
		fail(err)
	}
	return v
}

// obj writes a JSON object with its members in the order given: key, value, key, value. A
// json.RawMessage value goes in as it is, so a case can carry odd JSON on purpose.
func obj(kv ...any) json.RawMessage {
	var b bytes.Buffer
	b.WriteByte('{')
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(must(json.Marshal(kv[i].(string))))
		b.WriteByte(':')
		if r, ok := kv[i+1].(json.RawMessage); ok {
			b.Write(r)
		} else {
			b.Write(must(json.Marshal(kv[i+1])))
		}
	}
	b.WriteByte('}')
	return b.Bytes()
}

func raw(s string) json.RawMessage { return json.RawMessage(s) }

// sum256 and sum384 make fixed test values from a label.
func sum256(label string) []byte { h := sha256.Sum256([]byte(label)); return h[:] }
func sum384(label string) []byte { h := sha512.Sum384([]byte(label)); return h[:] }
func hex256(label string) string { return hex.EncodeToString(sum256(label)) }
func hex384(label string) string { return hex.EncodeToString(sum384(label)) }

func fill(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }

func hexPtr(b []byte) *string {
	if b == nil {
		return nil
	}
	s := hex.EncodeToString(b)
	return &s
}
