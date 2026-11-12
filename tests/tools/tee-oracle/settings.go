package main

import (
	"encoding/json"
	"strings"

	attest "github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/verify"
)

// settingsVerdict decodes the attestation settings as the signing client does (encoding/json)
// and validates them.
func settingsVerdict(att json.RawMessage) (bool, string) {
	var a verify.Attestation
	if err := json.Unmarshal(att, &a); err != nil {
		return false, "unmarshal: " + err.Error()
	}
	if err := a.Validate(); err != nil {
		return false, err.Error()
	}
	return true, ""
}

func settingsCases() []settingsCase {
	const host = "sharedweu.weu.attest.azure.net" // Microsoft's public shared MAA provider
	setup := hex256("setup")
	cce := hex256("cce policy")
	digest := "sha256:" + hex256("runner image")
	p0, p1, p2, p3 := hex384("pcr0"), hex384("pcr1"), hex384("pcr2"), hex384("pcr3")
	zero := strings.Repeat("0", 96)
	pcrs := func(kv ...any) json.RawMessage { return obj(kv...) }
	good3 := pcrs("0", p0, "1", p1, "2", p2)
	nitro := func(p json.RawMessage, kv ...any) json.RawMessage {
		return obj(append([]any{"verifier", "aws-nitro", "nitro_pcrs", p}, kv...)...)
	}
	azure := func(kv ...any) json.RawMessage {
		return obj(append([]any{"verifier", "azure-maa", "maa_host", host, "cce_policy_sha256", cce}, kv...)...)
	}
	azureHost := func(h string) json.RawMessage {
		return obj("verifier", "azure-maa", "maa_host", h, "cce_policy_sha256", cce)
	}
	azureCCE := func(c string) json.RawMessage {
		return obj("verifier", "azure-maa", "maa_host", host, "cce_policy_sha256", c)
	}
	tdx := []string{"GCP_INTEL_TDX"}
	gcp := func(kv ...any) json.RawMessage {
		return obj(append([]any{"verifier", "gcp-cs", "gcp_image_digest", digest, "gcp_audience", csAudience, "gcp_hwmodels", tdx}, kv...)...)
	}
	gcpDigest := func(d string) json.RawMessage {
		return obj("verifier", "gcp-cs", "gcp_image_digest", d, "gcp_audience", csAudience, "gcp_hwmodels", tdx)
	}
	gcpAud := func(a string) json.RawMessage {
		return obj("verifier", "gcp-cs", "gcp_image_digest", digest, "gcp_audience", a, "gcp_hwmodels", tdx)
	}
	gcpModels := func(m ...string) json.RawMessage {
		return obj("verifier", "gcp-cs", "gcp_image_digest", digest, "gcp_audience", csAudience, "gcp_hwmodels", m)
	}
	dev := func(kv ...any) json.RawMessage { return obj(append([]any{"verifier", "dev"}, kv...)...) }

	cases := []struct {
		name string
		att  json.RawMessage
	}{
		{"verifier missing", raw(`{}`)},
		{"verifier empty", obj("verifier", "")},
		{"verifier unknown", obj("verifier", "sgx")},
		{"verifier upper case DEV", obj("verifier", "DEV")},
		{"verifier with trailing space", obj("verifier", "dev ")},
		{"verifier as a number", raw(`{"verifier":1}`)},
		{"verifier JSON key upper case (encoding/json matches names case-insensitively)", obj("VERIFIER", "dev")},
		{"nitro JSON keys in mixed case accepted", obj("Verifier", "aws-nitro", "Nitro_PCRs", good3)},
		{"unknown JSON field ignored", dev("extra", 1)},
		{"min_locked_version negative: unmarshal error", dev("setup_sha256", setup, "min_locked_version", -1)},
		{"min_locked_version as string: unmarshal error", dev("setup_sha256", setup, "min_locked_version", "3")},
		{"min_locked_version 3.0: unmarshal error", dev("setup_sha256", setup, "min_locked_version", raw("3.0"))},
		{"allow_unpinned_setup as string: unmarshal error", dev("allow_unpinned_setup", "true")},
		{"explicit nulls are like absent fields", dev("setup_sha256", nil, "nitro_pcrs", nil, "gcp_hwmodels", nil)},
		{"dev ok", dev()},
		{"dev allow_unpinned_setup ok", dev("allow_unpinned_setup", true)},
		{"dev allow_unpinned_setup with setup_sha256 refused", dev("setup_sha256", setup, "allow_unpinned_setup", true)},
		{"azure-maa allow_unpinned_setup refused", azure("allow_unpinned_setup", true)},
		{"aws-nitro allow_unpinned_setup refused", nitro(good3, "allow_unpinned_setup", true)},
		{"dev min_locked_version without setup_sha256", dev("min_locked_version", 2)},
		{"dev min_open_version without setup_sha256", dev("min_open_version", 2)},
		{"dev setup_sha256 ok", dev("setup_sha256", setup)},
		{"dev setup_sha256 with 0x ok", dev("setup_sha256", "0x"+setup)},
		{"dev setup_sha256 with 0X ok (lower-cased before the prefix trim)", dev("setup_sha256", "0X"+setup)},
		{"dev setup_sha256 upper case ok", dev("setup_sha256", strings.ToUpper(setup))},
		{"dev setup_sha256 63 digits", dev("setup_sha256", setup[:63])},
		{"dev setup_sha256 66 digits", dev("setup_sha256", setup+"00")},
		{"dev setup_sha256 not hex", dev("setup_sha256", "zz"+setup[2:])},
		{"dev setup_sha256 with leading space", dev("setup_sha256", " "+setup)},
		{"dev setup and min versions ok", dev("setup_sha256", setup, "min_locked_version", 3, "min_open_version", 2)},
		{"dev key_release_sha256 with setup_sha256 ok", dev("setup_sha256", setup, "key_release_sha256", hex256("key rule"))},
		{"dev key_release_sha256 without setup_sha256", dev("key_release_sha256", hex256("key rule"))},
		{"dev key_release_sha256 all zero", dev("setup_sha256", setup, "key_release_sha256", strings.Repeat("0", 64))},
		{"dev key_release_sha256 63 digits", dev("setup_sha256", setup, "key_release_sha256", hex256("key rule")[:63])},
		{"azure ok", azure()},
		{"azure maa_host missing", obj("verifier", "azure-maa", "cce_policy_sha256", cce)},
		{"azure maa_host with scheme", azureHost("https://" + host)},
		{"azure maa_host with path", azureHost(host + "/certs")},
		{"azure maa_host with trailing slash", azureHost(host + "/")},
		{"azure maa_host upper case ok (lower-cased)", azureHost("SharedWEU.WEU.attest.azure.net")},
		{"azure maa_host with port ok", azureHost(host + ":443")},
		{"azure maa_host IP and port ok", azureHost("127.0.0.1:8443")},
		{"azure maa_host port of 6 digits", azureHost(host + ":123456")},
		{"azure maa_host trailing dot", azureHost(host + ".")},
		{"azure maa_host leading hyphen", azureHost("-" + host)},
		{"azure maa_host underscore", azureHost("shared_weu.attest.azure.net")},
		{"azure maa_host empty port", azureHost(host + ":")},
		{"azure cce_policy_sha256 missing", obj("verifier", "azure-maa", "maa_host", host)},
		{"azure cce_policy_sha256 63 digits", azureCCE(cce[:63])},
		{"azure cce_policy_sha256 upper case ok", azureCCE(strings.ToUpper(cce))},
		{"azure cce_policy_sha256 with 0x refused (no prefix trim here)", azureCCE("0x" + cce)},
		{"azure compliance_status cvm ok", azure("compliance_status", "azure-compliant-cvm")},
		{"azure compliance_status uvm ok", azure("compliance_status", "azure-compliant-uvm")},
		{"azure compliance_status other", azure("compliance_status", "azure-compliant")},
		{"azure compliance_status upper case", azure("compliance_status", "AZURE-COMPLIANT-UVM")},
		{"azure key_release_sha256 with setup_sha256 ok", azure("setup_sha256", setup, "key_release_sha256", hex256("key rule"))},
		{"nitro ok with 0,1,2", nitro(good3)},
		{"nitro ok with 0,1,2,3 and 31", nitro(pcrs("0", p0, "1", p1, "2", p2, "3", p3, "31", p3))},
		{"nitro pcr upper case hex ok", nitro(pcrs("0", p0, "1", strings.ToUpper(p1), "2", p2))},
		{"nitro_pcrs missing", obj("verifier", "aws-nitro")},
		{"nitro_pcrs empty object", nitro(raw(`{}`))},
		{"nitro_pcrs as an array", nitro(raw(`["` + p0 + `"]`))},
		{"nitro pcr2 missing", nitro(pcrs("0", p0, "1", p1))},
		{"nitro pcr0 all zero", nitro(pcrs("0", zero, "1", p1, "2", p2))},
		{"nitro pcr8 all zero ok (only 0-2 checked)", nitro(pcrs("0", p0, "1", p1, "2", p2, "8", zero))},
		{"nitro key 01", nitro(pcrs("0", p0, "01", p1, "2", p2))},
		{"nitro key 32", nitro(pcrs("0", p0, "1", p1, "2", p2, "32", p3))},
		{"nitro key -1", nitro(pcrs("-1", p1, "0", p0, "1", p1, "2", p2))},
		{"nitro key +1", nitro(pcrs("+1", p1, "0", p0, "2", p2))},
		{"nitro key pcr3", nitro(pcrs("0", p0, "1", p1, "2", p2, "pcr3", p3))},
		{"nitro pcr 95 hex digits", nitro(pcrs("0", p0, "1", p1, "2", p2[:95]))},
		{"nitro pcr 64 hex digits (SHA-256)", nitro(pcrs("0", p0, "1", p1, "2", p2[:64]))},
		{"nitro pcr with 0x refused", nitro(pcrs("0", p0, "1", "0x"+p1, "2", p2))},
		{"nitro_root_sha256 correct ok", nitro(good3, "nitro_root_sha256", attest.NitroRootSHA256)},
		{"nitro_root_sha256 correct upper case ok", nitro(good3, "nitro_root_sha256", strings.ToUpper(attest.NitroRootSHA256))},
		{"nitro_root_sha256 other value", nitro(good3, "nitro_root_sha256", hex256("other root"))},
		{"nitro_root_sha256 63 digits", nitro(good3, "nitro_root_sha256", attest.NitroRootSHA256[:63])},
		{"gcp ok", gcp()},
		{"gcp digest without sha256: ok", gcpDigest(hex256("runner image"))},
		{"gcp digest SHA256: upper case ok", gcpDigest(strings.ToUpper(digest))},
		{"gcp digest bad hex", gcpDigest(digest[:len(digest)-2] + "zz")},
		{"gcp digest sha384:", gcpDigest("sha384:" + hex256("runner image"))},
		{"gcp digest missing", obj("verifier", "gcp-cs", "gcp_audience", csAudience, "gcp_hwmodels", tdx)},
		{"gcp audience missing", obj("verifier", "gcp-cs", "gcp_image_digest", digest, "gcp_hwmodels", tdx)},
		{"gcp audience STS", gcpAud("https://sts.googleapis.com")},
		{"gcp audience STS with trailing slash (exact compare: accepted)", gcpAud("https://sts.googleapis.com/")},
		{"gcp audience //iam.googleapis.com/x", gcpAud("//iam.googleapis.com/x")},
		{"gcp audience https://iam.googleapis.com/x", gcpAud("https://iam.googleapis.com/x")},
		{"gcp hwmodels missing", obj("verifier", "gcp-cs", "gcp_image_digest", digest, "gcp_audience", csAudience)},
		{"gcp hwmodels empty list", gcpModels()},
		{"gcp hwmodels GCP_SHIELDED_VM", gcpModels("GCP_SHIELDED_VM")},
		{"gcp hwmodels gcp_shielded_vm lower case (EqualFold)", gcpModels("gcp_shielded_vm")},
		{"gcp hwmodel with inner space (only TrimSpace checked: accepted)", gcpModels("GCP INTEL_TDX")},
		{"gcp hwmodel with trailing space", gcpModels("GCP_INTEL_TDX ")},
		{"gcp hwmodel empty string", gcpModels("")},
		{"gcp hwmodels AMD and Intel ok", gcpModels("GCP_AMD_SEV", "GCP_INTEL_TDX")},
		{"gcp issuer explicit default ok", gcp("gcp_issuer", csIssuer)},
		{"gcp issuer with port ok", gcp("gcp_issuer", "https://issuer.example:8443")},
		{"gcp issuer http", gcp("gcp_issuer", "http://issuer.example")},
		{"gcp issuer with path", gcp("gcp_issuer", "https://issuer.example/x")},
		{"gcp issuer trailing slash", gcp("gcp_issuer", "https://issuer.example/")},
		{"gcp issuer with query", gcp("gcp_issuer", "https://issuer.example?x=1")},
		{"gcp issuer with empty query", gcp("gcp_issuer", "https://issuer.example?")},
		{"gcp issuer with fragment", gcp("gcp_issuer", "https://issuer.example#x")},
		{"gcp issuer with user info", gcp("gcp_issuer", "https://user@issuer.example")},
		{"gcp issuer without host", gcp("gcp_issuer", "https://")},
		{"gcp issuer HTTPS upper case scheme (url.Parse lower-cases the scheme)", gcp("gcp_issuer", "HTTPS://issuer.example")},
		{"gcp service account ok", gcp("gcp_service_account", gcpAccount)},
		{"gcp service account without @", gcp("gcp_service_account", "signer.example-project.iam.gserviceaccount.com")},
		{"gcp service account with space", gcp("gcp_service_account", "signer @example-project.iam.gserviceaccount.com")},
		{"gcp project id ok", gcp("gcp_project_id", gcpProject)},
		{"gcp project id upper case", gcp("gcp_project_id", "Example-Project")},
		{"gcp project id too short", gcp("gcp_project_id", "abcde")},
		{"gcp project id 6 chars ok", gcp("gcp_project_id", "abcdef")},
		{"gcp project id 31 chars", gcp("gcp_project_id", "a"+strings.Repeat("b", 30))},
		{"gcp project id ends with hyphen", gcp("gcp_project_id", "example-")},
		{"gcp project id starts with digit", gcp("gcp_project_id", "1example")},
		{"foreign nitro_pcrs on azure-maa", azure("nitro_pcrs", good3)},
		{"foreign maa_host on gcp-cs", gcp("maa_host", host)},
		{"foreign gcp_audience on dev", dev("gcp_audience", csAudience)},
		{"foreign compliance_status on aws-nitro", nitro(good3, "compliance_status", "azure-compliant-uvm")},
		{"foreign nitro_root_sha256 on gcp-cs", gcp("nitro_root_sha256", attest.NitroRootSHA256)},
		{"foreign gcp_project_id on azure-maa", azure("gcp_project_id", gcpProject)},
		{"foreign maa_host on dev", dev("maa_host", host)},
		{"foreign setting with unknown verifier (verifier error first)", obj("verifier", "sgx", "maa_host", host)},
		{"foreign setting checked before own settings", obj("verifier", "azure-maa", "gcp_audience", "x")},
	}
	out := make([]settingsCase, 0, len(cases))
	for _, c := range cases {
		ok, why := settingsVerdict(c.att)
		out = append(out, settingsCase{Name: c.name, Attestation: c.att, Valid: ok, Error: why})
	}
	return out
}
