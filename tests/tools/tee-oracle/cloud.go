package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	backend "github.com/lidofinance/tee-signer/signer-protocol"
)

// Fixed values of the cloud cases. None is a real host, project or account.
const (
	maaHost       = "maa.attest.example"
	csIssuer      = "https://confidentialcomputing.googleapis.com"
	csAudience    = "signer-runner-identity"
	gcpProject    = "example-project"
	gcpAccount    = "signer@example-project.iam.gserviceaccount.com"
	gcpInstanceID = "1234567890123456789"
)

var (
	cceHex    = hex256("cce policy")
	digestHex = "sha256:" + hex256("runner image")
)

func reportData(runtime []byte) string {
	h := sha256.Sum256(runtime)
	return hex.EncodeToString(h[:]) + strings.Repeat("00", 32)
}

// maaClaims are the claims of a good MAA token for an SEV-SNP container group, issued at iat
// for the runner's user data ud.
func maaClaims(iat int64, ud []byte) map[string]any {
	runtime := backend.MAARuntimeData(ud)
	var rt map[string]any
	if err := json.Unmarshal(runtime, &rt); err != nil {
		fail(err)
	}
	return map[string]any{
		"exp":                             iat + 8*3600,
		"iat":                             iat,
		"iss":                             "https://" + maaHost,
		"jti":                             hex256("jti"),
		"nbf":                             iat,
		"x-ms-attestation-type":           "sevsnpvm",
		"x-ms-compliance-status":          "azure-compliant-uvm",
		"x-ms-policy-hash":                b64(sum256("policy")),
		"x-ms-runtime":                    rt,
		"x-ms-sevsnpvm-hostdata":          cceHex,
		"x-ms-sevsnpvm-is-debuggable":     false,
		"x-ms-sevsnpvm-launchmeasurement": hex384("launch measurement"),
		"x-ms-sevsnpvm-reportdata":        reportData(runtime),
		"x-ms-sevsnpvm-smt-allowed":       true,
		"x-ms-sevsnpvm-uvm-endorsement": map[string]any{
			"x-ms-sevsnpvm-guestsvn":          "100",
			"x-ms-sevsnpvm-launchmeasurement": hex384("launch measurement"),
		},
		"x-ms-sevsnpvm-vmpl": 0,
		"x-ms-ver":           "1.0",
	}
}

// guestClaims turn good MAA claims into a confidential VM guest attestation token: type
// azurevm, the hardware claims nested in x-ms-isolation-tee.
func guestClaims(c map[string]any) {
	nested := map[string]any{"x-ms-attestation-type": "sevsnpvm", "x-ms-compliance-status": "azure-compliant-cvm"}
	for _, k := range []string{"x-ms-sevsnpvm-hostdata", "x-ms-sevsnpvm-is-debuggable", "x-ms-sevsnpvm-launchmeasurement",
		"x-ms-sevsnpvm-reportdata", "x-ms-sevsnpvm-vmpl"} {
		nested[k] = c[k]
	}
	c["x-ms-attestation-type"] = "azurevm"
	c["x-ms-compliance-status"] = "azure-compliant-cvm"
	c["x-ms-isolation-tee"] = nested
}

func gcpClaims(iat int64, ud []byte) map[string]any {
	return map[string]any{
		"aud":          csAudience,
		"exp":          iat + 3600,
		"iat":          iat,
		"nbf":          iat,
		"iss":          csIssuer,
		"sub":          "https://www.googleapis.com/compute/v1/projects/" + gcpProject + "/zones/europe-west4-a/instances/" + gcpInstanceID,
		"eat_nonce":    hex.EncodeToString(ud),
		"eat_profile":  "https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims",
		"secboot":      true,
		"oemid":        11129,
		"hwmodel":      "GCP_INTEL_TDX",
		"swname":       "CONFIDENTIAL_SPACE",
		"swversion":    []string{"260900"},
		"attester_tcb": []string{"INTEL"},
		"dbgstat":      "disabled-since-boot",
		"submods": map[string]any{
			"confidential_space": map[string]any{"support_attributes": []string{"LATEST", "STABLE", "USABLE"}},
			"container": map[string]any{
				"args":            []string{"/signer-runner"},
				"image_digest":    digestHex,
				"image_reference": "registry.example/signer-runner@" + digestHex,
				"restart_policy":  "Never",
			},
			"gce": map[string]any{
				"instance_id":    gcpInstanceID,
				"instance_name":  "signer-runner-1",
				"project_id":     gcpProject,
				"project_number": "123456789012",
				"zone":           "europe-west4-a",
			},
		},
		"google_service_accounts": []string{gcpAccount},
	}
}

// split and join edit the parts of a compact token.
func split(t string) []string { return strings.Split(t, ".") }
func join(p []string) string  { return strings.Join(p, ".") }

func flipSig(t string) string {
	p := split(t)
	sig, _ := base64.RawURLEncoding.DecodeString(p[2])
	sig[len(sig)/2] ^= 0x01
	p[2] = b64(sig)
	return join(p)
}

func prepend(member string) func(p []byte) []byte {
	return func(p []byte) []byte { return append([]byte("{"+member+","), p[1:]...) }
}

func (g *gen) azureCases() []identityCase {
	nonce := sum256("azure nonce")
	other := sum256("other nonce")
	iat := g.now.Unix() - 60
	keys := jwks(jwk("k1", g.k1), jwk("k2", g.k2))
	issuer := "https://" + maaHost
	azAtt := func(kv ...any) json.RawMessage {
		return obj(append([]any{"verifier", "azure-maa", "maa_host", maaHost, "cce_policy_sha256", cceHex, "setup_sha256", setupHex}, kv...)...)
	}
	att := azAtt()
	cvm := azAtt("compliance_status", "azure-compliant-cvm")
	claims := func(ud []byte) map[string]any { return maaClaims(iat, ud) }
	tok := func(s tokSpec) []byte { return g.cloud("azure", "azure-maa-jwt", setupState, nonce, claims, s) }
	var cs []identityCase
	add := func(name string, a json.RawMessage, idb []byte) {
		cs = append(cs, g.idCase(name, a, keys, issuer, nonce, idb))
	}
	c := func(name string, s tokSpec) { add(name, att, tok(s)) }
	ex := func(v int64) any { return v }

	c("azure good", tokSpec{})
	c("azure signed with k2 under kid k2", tokSpec{key: g.k2, header: header("k2")})
	c("azure signed with k2 under kid k1", tokSpec{key: g.k2})
	c("azure bad signature bit", tokSpec{token: flipSig})
	c("azure signature empty", tokSpec{token: func(t string) string { p := split(t); p[2] = ""; return join(p) }})
	c("azure unknown kid", tokSpec{header: header("k9")})
	c("azure kid missing", tokSpec{header: obj("alg", "RS256", "typ", "JWT")})
	c("azure kid empty", tokSpec{header: header("")})
	c("azure kid as number", tokSpec{header: obj("alg", "RS256", "kid", 1, "typ", "JWT")})
	for _, alg := range []string{"none", "HS256", "PS256", "rs256"} {
		c("azure alg "+alg, tokSpec{header: obj("alg", alg, "kid", "k1", "typ", "JWT")})
	}
	c("azure alg missing", tokSpec{header: obj("kid", "k1", "typ", "JWT")})
	c("azure crit header", tokSpec{header: obj("alg", "RS256", "kid", "k1", "typ", "JWT", "crit", []string{"exp"})})
	c("azure header without typ", tokSpec{header: obj("alg", "RS256", "kid", "k1")})
	c("azure header with jku (ignored)", tokSpec{header: obj("alg", "RS256", "jku", "https://other.example/certs", "kid", "k1", "typ", "JWT")})
	c("azure header with duplicate member", tokSpec{header: []byte(`{"alg":"RS256","kid":"k9","kid":"k1","typ":"JWT"}`)})
	c("azure header not JSON", tokSpec{header: []byte("RS256 k1")})
	c("azure issuer other", tokSpec{claims: set("iss", "https://other.attest.example")})
	c("azure issuer with trailing slash", tokSpec{claims: set("iss", issuer+"/")})
	c("azure issuer upper case", tokSpec{claims: set("iss", strings.ToUpper(issuer))})
	c("azure issuer missing", tokSpec{claims: del("iss")})
	c("azure expired", tokSpec{claims: set("exp", ex(g.now.Unix()-3600))})
	c("azure expired 30 s ago (within the 1 min skew)", tokSpec{claims: set("exp", ex(g.now.Unix()-30))})
	c("azure nbf in the future", tokSpec{claims: set("nbf", ex(g.now.Unix()+3600))})
	c("azure nbf 30 s ahead (within skew)", tokSpec{claims: set("nbf", ex(g.now.Unix()+30))})
	c("azure iat in the future (+1h)", tokSpec{claims: set("iat", ex(g.now.Unix()+3600))})
	c("azure iat 30 s ahead (within skew)", tokSpec{claims: set("iat", ex(g.now.Unix()+30))})
	c("azure exp as a string", tokSpec{claims: set("exp", fmt.Sprint(iat+3600))})
	c("azure exp missing", tokSpec{claims: del("exp")})
	c("azure iat missing", tokSpec{claims: del("iat")})
	c("azure exp with a fraction", tokSpec{claims: set("exp", raw(fmt.Sprintf("%d.5", iat+3600)))})
	c("azure exp in exponent form 4.1e9", tokSpec{claims: set("exp", raw("4.1e9"))})
	c("azure exp past year 9999", tokSpec{claims: set("exp", raw("253402300800"))})
	c("azure iat negative", tokSpec{claims: set("iat", ex(-1))})
	c("azure debuggable true", tokSpec{claims: set("x-ms-sevsnpvm-is-debuggable", true)})
	c("azure is-debuggable missing", tokSpec{claims: del("x-ms-sevsnpvm-is-debuggable")})
	c("azure is-debuggable as string false", tokSpec{claims: set("x-ms-sevsnpvm-is-debuggable", "false")})
	c("azure is-debuggable as number 0", tokSpec{claims: set("x-ms-sevsnpvm-is-debuggable", 0)})
	c("azure vmpl 2", tokSpec{claims: set("x-ms-sevsnpvm-vmpl", 2)})
	c("azure vmpl missing", tokSpec{claims: del("x-ms-sevsnpvm-vmpl")})
	c("azure vmpl as string 0", tokSpec{claims: set("x-ms-sevsnpvm-vmpl", "0")})
	c("azure vmpl 0.0 (not an integer)", tokSpec{claims: set("x-ms-sevsnpvm-vmpl", raw("0.0"))})
	c("azure vmpl -0", tokSpec{claims: set("x-ms-sevsnpvm-vmpl", raw("-0"))})
	c("azure vmpl 0e0", tokSpec{claims: set("x-ms-sevsnpvm-vmpl", raw("0e0"))})
	c("azure TEE type other", tokSpec{claims: set("x-ms-attestation-type", "sgx")})
	c("azure TEE type upper case", tokSpec{claims: set("x-ms-attestation-type", "SEVSNPVM")})
	c("azure TEE type missing", tokSpec{claims: del("x-ms-attestation-type")})
	c("azure compliance cvm while aci expected", tokSpec{claims: set("x-ms-compliance-status", "azure-compliant-cvm")})
	c("azure compliance missing", tokSpec{claims: del("x-ms-compliance-status")})
	c("azure hostdata other", tokSpec{claims: set("x-ms-sevsnpvm-hostdata", hex256("other cce policy"))})
	c("azure hostdata upper case", tokSpec{claims: set("x-ms-sevsnpvm-hostdata", strings.ToUpper(cceHex))})
	c("azure hostdata missing", tokSpec{claims: del("x-ms-sevsnpvm-hostdata")})
	{
		ud := backend.IdentityUserData(nonce, identity(setupState))
		good := reportData(backend.MAARuntimeData(ud))
		c("azure report data over the raw user data", tokSpec{claims: set("x-ms-sevsnpvm-reportdata", reportData(ud))})
		c("azure report data upper case hex", tokSpec{claims: set("x-ms-sevsnpvm-reportdata", strings.ToUpper(good))})
		c("azure report data with a non-zero tail", tokSpec{claims: set("x-ms-sevsnpvm-reportdata", good[:126]+"01")})
		c("azure report data without the zero tail", tokSpec{claims: set("x-ms-sevsnpvm-reportdata", good[:64])})
		c("azure report data missing", tokSpec{claims: del("x-ms-sevsnpvm-reportdata")})
		otherUD := backend.IdentityUserData(other, identity(setupState))
		c("azure report data for another nonce", tokSpec{claims: set("x-ms-sevsnpvm-reportdata", reportData(backend.MAARuntimeData(otherUD)))})
		c("azure runtime claim for another nonce, report data right", tokSpec{claims: set("x-ms-runtime", map[string]any{"signer-runner-identity": hex.EncodeToString(otherUD)})})
	}
	add("azure azurevm guest attestation with nested x-ms-isolation-tee, cvm setting", cvm, tok(tokSpec{claims: guestClaims}))
	add("azure azurevm guest attestation without the nested object", cvm, tok(tokSpec{claims: func(m map[string]any) { guestClaims(m); delete(m, "x-ms-isolation-tee") }}))
	add("azure azurevm nested debuggable true, top level false", cvm, tok(tokSpec{claims: func(m map[string]any) {
		guestClaims(m)
		setPath(m, "x-ms-isolation-tee.x-ms-sevsnpvm-is-debuggable", true)
	}}))
	add("azure azurevm nested object is a string", cvm, tok(tokSpec{claims: func(m map[string]any) { guestClaims(m); m["x-ms-isolation-tee"] = "sevsnpvm" }}))
	add("azure azurevm nested hostdata other", cvm, tok(tokSpec{claims: func(m map[string]any) {
		guestClaims(m)
		setPath(m, "x-ms-isolation-tee.x-ms-sevsnpvm-hostdata", hex256("other cce policy"))
	}}))
	add("azure azurevm with aci setting", att, tok(tokSpec{claims: guestClaims}))
	add("azure sevsnpvm token with compliance cvm and cvm setting", cvm, tok(tokSpec{claims: set("x-ms-compliance-status", "azure-compliant-cvm")}))
	c("azure duplicate JSON member in payload", tokSpec{payload: prepend(`"iss":"https://other.attest.example"`)})
	c("azure duplicate member nested", tokSpec{payload: func(p []byte) []byte {
		return []byte(strings.Replace(string(p), `"x-ms-sevsnpvm-uvm-endorsement":{`, `"x-ms-sevsnpvm-uvm-endorsement":{"x-ms-sevsnpvm-guestsvn":"1",`, 1))
	}})
	c("azure nested objects without duplicates", tokSpec{claims: set("extra", map[string]any{"a": map[string]any{"b": 1}, "c": map[string]any{"b": 2}})})
	c("azure trailing data after the payload JSON", tokSpec{payload: func(p []byte) []byte { return append(p, []byte("{}")...) }})
	c("azure trailing whitespace after the payload JSON", tokSpec{payload: func(p []byte) []byte { return append(p, []byte(" \n")...) }})
	c("azure payload is a JSON array", tokSpec{payload: func(p []byte) []byte { return append(append([]byte("["), p...), ']') }})
	c("azure token with leading and trailing whitespace", tokSpec{token: func(t string) string { return " " + t + "\n" }})
	c("azure token with 2 parts", tokSpec{token: func(t string) string { p := split(t); return join(p[:2]) }})
	c("azure token with 4 parts", tokSpec{token: func(t string) string { return t + ".e30" }})
	c("azure padding = in base64url", tokSpec{token: func(t string) string { p := split(t); p[1] += "="; return join(p) }})
	c("azure standard base64 alphabet in signature", tokSpec{token: func(t string) string {
		p := split(t)
		p[2] = strings.NewReplacer("-", "+", "_", "/").Replace(p[2])
		return join(p)
	}})
	add("azure document of the dev platform while azure-maa is set", att,
		encode(bound(setupState, nonce, "dev", "dev-json", func(ud []byte) []byte { return devDoc(nonce, ud) })))
	add("azure platform azure with format dev-json", att,
		encode(bound(setupState, nonce, "azure", "dev-json", func(ud []byte) []byte { return []byte(g.jwt(maaClaims(iat, ud), tokSpec{})) })))
	add("azure setup pin mismatch with a good token", obj("verifier", "azure-maa", "maa_host", maaHost, "cce_policy_sha256", cceHex, "setup_sha256", hex256("other setup")), tok(tokSpec{}))
	add("azure runner with a setup and no pin, good token", obj("verifier", "azure-maa", "maa_host", maaHost, "cce_policy_sha256", cceHex), tok(tokSpec{}))
	add("azure flag-path runner and no pin, good token", obj("verifier", "azure-maa", "maa_host", maaHost, "cce_policy_sha256", cceHex),
		g.cloud("azure", "azure-maa-jwt", flagState, nonce, claims, tokSpec{}))
	add("azure flag-path runner with its hash pinned", obj("verifier", "azure-maa", "maa_host", maaHost, "cce_policy_sha256", cceHex, "setup_sha256", flagHex),
		g.cloud("azure", "azure-maa-jwt", flagState, nonce, claims, tokSpec{}))
	add("azure maa_host upper case in settings", obj("verifier", "azure-maa", "maa_host", strings.ToUpper(maaHost), "cce_policy_sha256", cceHex, "setup_sha256", setupHex), tok(tokSpec{}))
	add("azure cce_policy_sha256 upper case in settings", obj("verifier", "azure-maa", "maa_host", maaHost, "cce_policy_sha256", strings.ToUpper(cceHex), "setup_sha256", setupHex), tok(tokSpec{}))
	add("azure maa_host of another provider", obj("verifier", "azure-maa", "maa_host", "other.attest.example", "cce_policy_sha256", cceHex, "setup_sha256", setupHex), tok(tokSpec{}))
	c("azure import key changed after binding", tokSpec{after: func(id *backend.Identity) { id.ImportKey = sum256("other import key") }})
	{
		krState := setupState
		krState.KeyReleaseHash = root("key rule")
		idb := g.cloud("azure", "azure-maa-jwt", krState, nonce, claims, tokSpec{})
		add("azure key_release_sha256 pinned and matching", azAtt("key_release_sha256", hex256("key rule")), idb)
		add("azure key_release_sha256 pinned, runner reports another", azAtt("key_release_sha256", hex256("other key rule")), idb)
	}
	cs = append(cs, g.idCase("azure key set with a 1024-bit key refused", att, jwks(jwk("weak", g.weak)), issuer, nonce,
		tok(tokSpec{key: g.weak, header: header("weak")})))
	cs = append(cs, g.idCase("azure key set empty", att, raw(`{"keys":[]}`), issuer, nonce, tok(tokSpec{})))
	cs = append(cs, g.idCase("azure key set not served", att, nil, issuer, nonce, tok(tokSpec{})))
	return cs
}

func (g *gen) gcpCases() []identityCase {
	nonce := sum256("gcp nonce")
	other := sum256("other nonce")
	iat := g.now.Unix() - 60
	keys := jwks(jwk("k1", g.k1), jwk("k2", g.k2))
	gAtt := func(kv ...any) json.RawMessage {
		base := []any{"verifier", "gcp-cs", "gcp_image_digest", digestHex, "gcp_audience", csAudience, "gcp_hwmodels", []string{"GCP_INTEL_TDX"}}
		return obj(append(append(base, kv...), "setup_sha256", setupHex)...)
	}
	att := gAtt()
	claims := func(ud []byte) map[string]any { return gcpClaims(iat, ud) }
	tok := func(s tokSpec) []byte {
		return g.cloud("gcp", "gcp-confidential-space-jwt", setupState, nonce, claims, s)
	}
	ud := backend.IdentityUserData(nonce, identity(setupState))
	udHex := hex.EncodeToString(ud)
	var cs []identityCase
	add := func(name string, a json.RawMessage, idb []byte) {
		cs = append(cs, g.idCase(name, a, keys, csIssuer, nonce, idb))
	}
	c := func(name string, s tokSpec) { add(name, att, tok(s)) }
	ex := func(v int64) any { return v }

	c("gcp good", tokSpec{})
	c("gcp signed with k2 under kid k2", tokSpec{key: g.k2, header: header("k2")})
	c("gcp eat_nonce array with another value too", tokSpec{claims: set("eat_nonce", []string{hex256("x"), udHex})})
	c("gcp eat_nonce array with the value only", tokSpec{claims: set("eat_nonce", []string{udHex})})
	c("gcp wrong eat_nonce", tokSpec{claims: set("eat_nonce", hex256("x"))})
	c("gcp eat_nonce for another nonce", tokSpec{claims: set("eat_nonce", hex.EncodeToString(backend.IdentityUserData(other, identity(setupState))))})
	c("gcp eat_nonce upper case hex", tokSpec{claims: set("eat_nonce", strings.ToUpper(udHex))})
	c("gcp eat_nonce missing", tokSpec{claims: del("eat_nonce")})
	c("gcp eat_nonce array with a number", tokSpec{claims: set("eat_nonce", []any{1})})
	c("gcp aud array containing the audience", tokSpec{claims: set("aud", []string{"x", csAudience})})
	c("gcp aud array with the STS audience next to it", tokSpec{claims: set("aud", []string{csAudience, "https://sts.googleapis.com"})})
	c("gcp aud other", tokSpec{claims: set("aud", "other-audience")})
	c("gcp aud missing", tokSpec{claims: del("aud")})
	c("gcp aud upper case", tokSpec{claims: set("aud", strings.ToUpper(csAudience))})
	c("gcp wrong image digest", tokSpec{claims: set("submods.container.image_digest", "sha256:"+hex256("other image"))})
	c("gcp image digest upper case hex in token", tokSpec{claims: set("submods.container.image_digest", "sha256:"+strings.ToUpper(hex256("runner image")))})
	c("gcp image digest without sha256: in token", tokSpec{claims: set("submods.container.image_digest", hex256("runner image"))})
	c("gcp image digest missing", tokSpec{claims: del("submods.container.image_digest")})
	add("gcp image digest upper case in settings", obj("verifier", "gcp-cs", "gcp_image_digest", strings.ToUpper(digestHex), "gcp_audience", csAudience, "gcp_hwmodels", []string{"GCP_INTEL_TDX"}, "setup_sha256", setupHex), tok(tokSpec{}))
	add("gcp image digest without sha256: in settings", obj("verifier", "gcp-cs", "gcp_image_digest", hex256("runner image"), "gcp_audience", csAudience, "gcp_hwmodels", []string{"GCP_INTEL_TDX"}, "setup_sha256", setupHex), tok(tokSpec{}))
	c("gcp dbgstat enabled", tokSpec{claims: set("dbgstat", "enabled")})
	c("gcp dbgstat missing", tokSpec{claims: del("dbgstat")})
	c("gcp dbgstat upper case", tokSpec{claims: set("dbgstat", "DISABLED-SINCE-BOOT")})
	c("gcp swname other", tokSpec{claims: set("swname", "GCE")})
	c("gcp swname lower case", tokSpec{claims: set("swname", "confidential_space")})
	c("gcp secboot false", tokSpec{claims: set("secboot", false)})
	c("gcp secboot missing", tokSpec{claims: del("secboot")})
	c("gcp secboot as string true", tokSpec{claims: set("secboot", "true")})
	c("gcp no STABLE", tokSpec{claims: set("submods.confidential_space.support_attributes", []string{"LATEST", "USABLE"})})
	c("gcp support_attributes as a single string STABLE", tokSpec{claims: set("submods.confidential_space.support_attributes", "STABLE")})
	c("gcp support_attributes missing", tokSpec{claims: del("submods.confidential_space.support_attributes")})
	c("gcp support_attributes lower case stable", tokSpec{claims: set("submods.confidential_space.support_attributes", []string{"stable"})})
	c("gcp hwmodel not in list", tokSpec{claims: set("hwmodel", "GCP_AMD_SEV")})
	c("gcp hwmodel lower case", tokSpec{claims: set("hwmodel", "gcp_intel_tdx")})
	c("gcp hwmodel missing", tokSpec{claims: del("hwmodel")})
	add("gcp hwmodel in a list of two", obj("verifier", "gcp-cs", "gcp_image_digest", digestHex, "gcp_audience", csAudience, "gcp_hwmodels", []string{"GCP_AMD_SEV", "GCP_INTEL_TDX"}, "setup_sha256", setupHex), tok(tokSpec{}))
	sa := gAtt("gcp_service_account", gcpAccount)
	add("gcp service account required and present", sa, tok(tokSpec{}))
	add("gcp service account required and absent", sa, tok(tokSpec{claims: del("google_service_accounts")}))
	add("gcp service account required, token has another", sa, tok(tokSpec{claims: set("google_service_accounts", []string{"other@example-project.iam.gserviceaccount.com"})}))
	add("gcp service account required, token has it as a single string", sa, tok(tokSpec{claims: set("google_service_accounts", gcpAccount)}))
	add("gcp service account required, upper case in token", sa, tok(tokSpec{claims: set("google_service_accounts", []string{strings.ToUpper(gcpAccount)})}))
	pr := gAtt("gcp_project_id", gcpProject)
	add("gcp project id match", pr, tok(tokSpec{}))
	add("gcp project id mismatch", pr, tok(tokSpec{claims: set("submods.gce.project_id", "other-project")}))
	add("gcp project id required, gce missing", pr, tok(tokSpec{claims: del("submods.gce")}))
	add("gcp project id and service account both required and present", gAtt("gcp_service_account", gcpAccount, "gcp_project_id", gcpProject), tok(tokSpec{}))
	c("gcp expired", tokSpec{claims: set("exp", ex(g.now.Unix()-3600))})
	c("gcp nbf in the future", tokSpec{claims: set("nbf", ex(g.now.Unix()+3600))})
	c("gcp iat in the future (+1h)", tokSpec{claims: set("iat", ex(g.now.Unix()+3600))})
	c("gcp iat as a string", tokSpec{claims: set("iat", fmt.Sprint(iat))})
	c("gcp bad signature", tokSpec{token: flipSig})
	c("gcp unknown kid", tokSpec{header: header("k9")})
	c("gcp alg RS384", tokSpec{header: obj("alg", "RS384", "kid", "k1", "typ", "JWT")})
	c("gcp issuer other", tokSpec{claims: set("iss", "https://issuer.example")})
	c("gcp issuer with trailing slash", tokSpec{claims: set("iss", csIssuer+"/")})
	add("gcp custom issuer in settings and token", gAtt("gcp_issuer", "https://issuer.example"), tok(tokSpec{claims: set("iss", "https://issuer.example")}))
	add("gcp custom issuer in settings, default in token", gAtt("gcp_issuer", "https://issuer.example"), tok(tokSpec{}))
	c("gcp duplicate member nested in submods", tokSpec{payload: func(p []byte) []byte {
		return []byte(strings.Replace(string(p), `"container":{`, `"container":{"image_digest":"sha256:`+hex256("other image")+`",`, 1))
	}})
	add("gcp azure token while gcp-cs is set", att,
		encode(bound(setupState, nonce, "azure", "azure-maa-jwt", func(ud []byte) []byte { return []byte(g.jwt(maaClaims(iat, ud), tokSpec{})) })))
	add("gcp runner with a setup and no pin", obj("verifier", "gcp-cs", "gcp_image_digest", digestHex, "gcp_audience", csAudience, "gcp_hwmodels", []string{"GCP_INTEL_TDX"}), tok(tokSpec{}))
	add("gcp setup pin mismatch", obj("verifier", "gcp-cs", "gcp_image_digest", digestHex, "gcp_audience", csAudience, "gcp_hwmodels", []string{"GCP_INTEL_TDX"}, "setup_sha256", hex256("other setup")), tok(tokSpec{}))
	add("gcp min_locked_version unmet", gAtt("min_locked_version", 4), tok(tokSpec{}))
	add("gcp min_locked_version met", gAtt("min_locked_version", 3), tok(tokSpec{}))
	c("gcp TLS key hash changed after binding", tokSpec{after: func(id *backend.Identity) { id.TLSKeyHash = sum256("other tls key") }})
	return cs
}
