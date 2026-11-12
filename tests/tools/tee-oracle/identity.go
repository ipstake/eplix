package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	backend "github.com/lidofinance/tee-signer/signer-protocol"
)

func root(label string) backend.Root { return backend.Root(sum256(label)) }

// The setup states of the identity cases: a runner on the flag path (no setup: the hash of
// its config file, the rest zero) and a runner with a setup.
var (
	flagState  = backend.SetupState{SetupHash: root("chain config")}
	setupState = backend.SetupState{
		SetupHash:       root("setup"),
		Locked:          backend.ConfigGroup{Version: 3, Hash: root("locked v3")},
		Open:            backend.ConfigGroup{Version: 2, Hash: root("open v2")},
		ApproverSetHash: root("approver set"),
		KeyOrigin:       backend.KeyOrigin{Imported: 4},
	}
	setupHex = hex.EncodeToString(sum256("setup"))
	flagHex  = hex.EncodeToString(sum256("chain config"))
)

func (g *gen) identityCases() []identityCase {
	var cs []identityCase
	cs = append(cs, g.devCases()...)
	cs = append(cs, g.wireCases()...)
	cs = append(cs, g.azureCases()...)
	cs = append(cs, g.gcpCases()...)
	return cs
}

func devDoc(nonce, ud []byte) []byte { return obj("nonce", nonce, "user_data", ud) }

func dev(state backend.SetupState, nonce []byte, doc func(ud []byte) []byte) []byte {
	return encode(bound(state, nonce, "dev", "dev-json", doc))
}

func (g *gen) devCases() []identityCase {
	nonce := sum256("identity nonce")
	other := sum256("other nonce")
	att := obj("verifier", "dev")
	pinned := obj("verifier", "dev", "setup_sha256", setupHex)
	std := func(ud []byte) []byte { return devDoc(nonce, ud) }
	var cs []identityCase
	add := func(name string, a json.RawMessage, n []byte, idb []byte) {
		cs = append(cs, g.idCase(name, a, nil, "", n, idb))
	}
	docCase := func(name string, doc func(ud []byte) []byte) { add(name, att, nonce, dev(flagState, nonce, doc)) }
	// text writes the dev document with the nonce member as given.
	text := func(ud []byte, nonceJSON string) []byte {
		return []byte(`{"nonce":` + nonceJSON + `,"user_data":"` + base64.StdEncoding.EncodeToString(ud) + `"}`)
	}

	add("dev good flag-path runner unpinned", att, nonce, dev(flagState, nonce, std))
	add("dev good setup pinned", pinned, nonce, dev(setupState, nonce, std))
	add("dev good setup pinned upper case 0X", obj("verifier", "dev", "setup_sha256", "0X"+strings.ToUpper(setupHex)), nonce, dev(setupState, nonce, std))
	docCase("dev doc for another nonce", func(ud []byte) []byte { return devDoc(other, ud) })
	docCase("dev doc user_data wrong", func(ud []byte) []byte { return devDoc(nonce, sum256("x")) })
	docCase("dev doc user_data empty", func(ud []byte) []byte { return devDoc(nonce, []byte{}) })
	add("dev platform dev format other", att, nonce, encode(bound(flagState, nonce, "dev", "dev-cbor", std)))
	add("dev platform other format dev-json", att, nonce, encode(bound(flagState, nonce, "nitro", "dev-json", std)))
	add("dev platform upper case DEV", att, nonce, encode(bound(flagState, nonce, "DEV", "dev-json", std)))
	docCase("dev malformed JSON doc", func(ud []byte) []byte { d := devDoc(nonce, ud); return d[:len(d)-1] })
	docCase("dev empty doc", func(ud []byte) []byte { return []byte{} })
	docCase("dev doc is a JSON array", func(ud []byte) []byte { return append(append([]byte("["), devDoc(nonce, ud)...), ']') })
	docCase("dev doc with trailing garbage", func(ud []byte) []byte { return append(devDoc(nonce, ud), 'x') })
	docCase("dev doc with leading and trailing whitespace", func(ud []byte) []byte { return []byte(" \n" + string(devDoc(nonce, ud)) + "\t ") })
	docCase("dev doc with extra fields", func(ud []byte) []byte { return obj("nonce", nonce, "user_data", ud, "extra", 1, "platform", "dev") })
	docCase("dev doc keys Nonce and USER_DATA (case-insensitive match)", func(ud []byte) []byte { return obj("Nonce", nonce, "USER_DATA", ud) })
	docCase("dev doc duplicate nonce, wrong first and right last", func(ud []byte) []byte { return obj("nonce", other, "nonce", nonce, "user_data", ud) })
	docCase("dev doc duplicate nonce, right first and wrong last", func(ud []byte) []byte { return obj("nonce", nonce, "nonce", other, "user_data", ud) })
	docCase("dev doc nonce base64 with an escaped newline", func(ud []byte) []byte {
		s := base64.StdEncoding.EncodeToString(nonce)
		return text(ud, `"`+s[:8]+`\n`+s[8:]+`"`)
	})
	docCase("dev doc nonce base64 without padding", func(ud []byte) []byte { return text(ud, `"`+base64.RawStdEncoding.EncodeToString(nonce)+`"`) })
	{
		n := fill(32, 0xff)
		add("dev doc nonce base64url alphabet", att, n, dev(flagState, n, func(ud []byte) []byte {
			return text(ud, `"`+base64.URLEncoding.EncodeToString(n)+`"`)
		}))
	}
	docCase("dev doc nonce as hex string", func(ud []byte) []byte { return text(ud, `"`+hex.EncodeToString(nonce)+`"`) })
	docCase("dev doc nonce null", func(ud []byte) []byte { return text(ud, `null`) })
	docCase("dev doc nonce missing", func(ud []byte) []byte { return obj("user_data", ud) })
	docCase("dev doc nonce as a number", func(ud []byte) []byte { return text(ud, `1`) })
	{
		empty := []byte{}
		add("dev empty nonce, doc nonce empty string", att, empty, dev(flagState, empty, func(ud []byte) []byte { return text(ud, `""`) }))
		add("dev empty nonce, doc nonce null", att, empty, dev(flagState, empty, func(ud []byte) []byte { return text(ud, `null`) }))
	}
	after := func(f func(id *backend.Identity)) []byte {
		id := bound(flagState, nonce, "dev", "dev-json", std)
		f(id)
		return encode(id)
	}
	add("dev import key changed after binding", att, nonce, after(func(id *backend.Identity) { id.ImportKey = sum256("other import key") }))
	add("dev TLS key hash changed after binding", att, nonce, after(func(id *backend.Identity) { id.TLSKeyHash = sum256("other tls key") }))
	add("dev import suite changed after binding", att, nonce, after(func(id *backend.Identity) { id.ImportAEAD = 0x0001 }))
	add("dev setup state changed after binding", att, nonce, after(func(id *backend.Identity) { id.State.KeyOrigin.Imported = 9 }))
	add("dev verified with another nonce than the one in the doc", att, other, dev(flagState, nonce, std))

	// Setup pins.
	st := func(f func(s *backend.SetupState)) []byte {
		s := setupState
		f(&s)
		return dev(s, nonce, std)
	}
	withSetup := dev(setupState, nonce, std)
	flagRunner := dev(flagState, nonce, std)
	add("dev setup pin mismatch", obj("verifier", "dev", "setup_sha256", hex256("other setup")), nonce, withSetup)
	add("dev runner with a setup and no pin", att, nonce, withSetup)
	add("dev allow_unpinned_setup with a setup", obj("verifier", "dev", "allow_unpinned_setup", true), nonce, withSetup)
	add("dev allow_unpinned_setup flag path", obj("verifier", "dev", "allow_unpinned_setup", true), nonce, flagRunner)
	add("dev flag-path runner with its hash pinned", obj("verifier", "dev", "setup_sha256", flagHex), nonce, flagRunner)
	add("dev flag-path runner with another hash pinned", obj("verifier", "dev", "setup_sha256", setupHex), nonce, flagRunner)
	minV := func(locked, open int) json.RawMessage {
		kv := []any{"verifier", "dev", "setup_sha256", setupHex}
		if locked > 0 {
			kv = append(kv, "min_locked_version", locked)
		}
		if open > 0 {
			kv = append(kv, "min_open_version", open)
		}
		return obj(kv...)
	}
	past := uint64(g.now.Unix() - 86400)
	future := uint64(g.now.Unix() + 86400)
	lockedPending := func(at uint64) []byte {
		return st(func(s *backend.SetupState) {
			s.Locked.Pending = backend.PendingUpdate{Version: 4, Hash: root("locked v4"), EffectiveAt: at}
		})
	}
	add("dev min_locked_version met", minV(3, 0), nonce, withSetup)
	add("dev min_locked_version unmet", minV(4, 0), nonce, withSetup)
	add("dev pending locked update effective in the past counts (min 4)", minV(4, 0), nonce, lockedPending(past))
	add("dev pending locked update effective in the future does not count (min 4)", minV(4, 0), nonce, lockedPending(future))
	add("dev pending locked update in the future, min 3 met by active", minV(3, 0), nonce, lockedPending(future))
	add("dev pending locked update in the past, min 5 unmet", minV(5, 0), nonce, lockedPending(past))
	add("dev min_open_version met", minV(0, 2), nonce, withSetup)
	add("dev min_open_version unmet", minV(0, 3), nonce, withSetup)
	add("dev pending open update effective in the past counts (min_open 3)", minV(0, 3), nonce,
		st(func(s *backend.SetupState) {
			s.Open.Pending = backend.PendingUpdate{Version: 3, Hash: root("open v3"), EffectiveAt: past}
		}))
	add("dev min_open met but min_locked unmet", minV(4, 2), nonce, withSetup)
	flagPlus := func(f func(s *backend.SetupState)) []byte {
		s := flagState
		f(&s)
		return dev(s, nonce, std)
	}
	add("dev imported keys only with flag-path setup hash, no pin", att, nonce, flagPlus(func(s *backend.SetupState) { s.KeyOrigin.Imported = 1 }))
	add("dev key_release_hash only with flag-path setup hash, no pin", att, nonce, flagPlus(func(s *backend.SetupState) { s.KeyReleaseHash = root("key rule") }))
	add("dev approver set hash only with flag-path setup hash, no pin", att, nonce, flagPlus(func(s *backend.SetupState) { s.ApproverSetHash = root("approver set") }))
	add("dev pending handover order with pin (pins ignore orders)", pinned, nonce,
		st(func(s *backend.SetupState) { s.Order = backend.Order{Kind: 1, Hash: root("order"), ActAt: future} }))
	krState := st(func(s *backend.SetupState) { s.KeyReleaseHash = root("key rule") })
	kr := func(h string) json.RawMessage {
		return obj("verifier", "dev", "setup_sha256", setupHex, "key_release_sha256", h)
	}
	add("dev key_release_sha256 pinned and matching", kr(hex256("key rule")), nonce, krState)
	add("dev key_release_sha256 pinned, runner reports another", kr(hex256("other key rule")), nonce, krState)
	add("dev key_release_sha256 pinned, runner reports none", kr(hex256("key rule")), nonce, withSetup)
	return cs
}

// wireCases are IDENTITY answers that do not decode, and one that does as a control.
func (g *gen) wireCases() []identityCase {
	nonce := sum256("identity nonce")
	att := obj("verifier", "dev", "setup_sha256", setupHex)
	std := func(ud []byte) []byte { return devDoc(nonce, ud) }
	good := dev(setupState, nonce, std)
	var cs []identityCase
	add := func(name string, idb []byte) { cs = append(cs, g.idCase(name, att, nil, "", nonce, idb)) }
	mut := func(f func(b []byte) []byte) []byte { return f(slices.Clone(good)) }
	st := func(f func(s *backend.SetupState)) []byte {
		s := setupState
		f(&s)
		return dev(s, nonce, std)
	}
	add("identity good (control)", good)
	add("identity version byte 2", mut(func(b []byte) []byte { b[0] = 2; return b }))
	add("identity version byte 3", mut(func(b []byte) []byte { b[0] = 3; return b }))
	add("identity with a trailing byte", mut(func(b []byte) []byte { return append(b, 0) }))
	add("identity cut short by one byte", mut(func(b []byte) []byte { return b[:len(b)-1] }))
	add("identity empty", []byte{})
	add("identity pending update not above the active version", st(func(s *backend.SetupState) {
		s.Locked.Pending = backend.PendingUpdate{Version: 3, Hash: root("locked v3b"), EffectiveAt: 1}
	}))
	add("identity empty pending update with a hash", st(func(s *backend.SetupState) {
		s.Open.Pending = backend.PendingUpdate{Hash: root("x")}
	}))
	add("identity order of kind 2", st(func(s *backend.SetupState) { s.Order = backend.Order{Kind: 2, Hash: root("order"), ActAt: 1} }))
	add("identity order kind 0 with a time", st(func(s *backend.SetupState) { s.Order = backend.Order{ActAt: 5} }))
	// The setup state ends with 4 reserved bytes, the imported count (4 bytes) and 32 reserved
	// bytes; the identity puts one version byte in front of it.
	end := 1 + backend.SetupStateLen
	add("identity reserved bytes before the imported count not zero", mut(func(b []byte) []byte { b[end-40] = 1; return b }))
	add("identity reserved bytes after the imported count not zero", mut(func(b []byte) []byte { b[end-1] = 1; return b }))
	return cs
}
