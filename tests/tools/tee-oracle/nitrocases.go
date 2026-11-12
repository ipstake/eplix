package main

import (
	"crypto/x509"
	"slices"
	"strconv"
	"time"
)

// nitroCases are the NSM document cases: a good document from the local test CA and one
// change each to its CBOR encoding, COSE layout, payload fields, chain, signature, PCRs,
// nonce, user data and time.
func (g *gen) nitroCases() []nitroCase {
	at := g.now
	ca, other := g.ca, g.otherCA
	nonce := sum256("nitro nonce")
	ud := sum256("nitro user data")
	tsMs := at.UnixMilli()
	pcrs := defaultPCRs()
	want := map[int][]byte{0: pcrs[0], 1: pcrs[1], 2: pcrs[2]}
	base := func() nitroOpts {
		return nitroOpts{roots: []*x509.Certificate{ca.root}, pcrs: want, nonce: nonce, userData: ud, now: at}
	}
	with := func(f func(o *nitroOpts)) nitroOpts { o := base(); f(&o); return o }
	pins := func(extra map[int][]byte) func(o *nitroOpts) {
		return func(o *nitroOpts) {
			m := map[int][]byte{0: pcrs[0], 1: pcrs[1], 2: pcrs[2]}
			for k, v := range extra {
				m[k] = v
			}
			o.pcrs = m
		}
	}
	fields := ca.payload(tsMs, pcrEntries(pcrs), nonce, ud)
	good := cMap(fields)
	doc := func(es []entry) []byte { return ca.cose(coseSpec{payload: cMap(es)}) }
	plain := ca.cose(coseSpec{payload: good})
	pcrsWith := func(f func(m map[uint64][]byte)) []entry {
		m := defaultPCRs()
		f(m)
		return setField(fields, "pcrs", cMap(pcrEntries(m)))
	}
	flip := func(b []byte, i int) []byte { c := slices.Clone(b); c[i] ^= 0x01; return c }
	dupDigest := append(slices.Clone(fields), entry{cText("digest"), cText("SHA384")})
	var cs []nitroCase
	add := func(name string, d []byte, o nitroOpts) { cs = append(cs, g.nitroCase(name, d, o)) }

	// CBOR and COSE encoding.
	add("synthetic good", plain, base())
	add("synthetic good tagged (0xd2)", ca.cose(coseSpec{payload: good, prefix: []byte{0xd2}}), base())
	add("synthetic tag 18 twice", ca.cose(coseSpec{payload: good, prefix: []byte{0xd2, 0xd2}}), base())
	add("synthetic tag 17 instead of 18", ca.cose(coseSpec{payload: good, prefix: []byte{0xd1}}), base())
	add("synthetic indefinite-length payload map", ca.cose(coseSpec{payload: cMapIndef(fields)}), base())
	add("synthetic indefinite-length outer array", ca.cose(coseSpec{payload: good, indefOuter: true}), base())
	add("synthetic indefinite-length protected header map", ca.cose(coseSpec{payload: good, protected: cMapIndef([]entry{{cUint(1), cNeg(-35)}})}), base())
	add("synthetic duplicate CBOR map key in payload", doc(dupDigest), base())
	add("synthetic duplicate key in indefinite-length payload map", ca.cose(coseSpec{payload: cMapIndef(dupDigest)}), base())
	add("synthetic duplicate PCR index", doc(setField(fields, "pcrs", cMap(append(pcrEntries(pcrs), entry{cUint(2), cBytes(pcrs[2])})))), base())
	add("synthetic indefinite-length pcrs map", doc(setField(fields, "pcrs", cMapIndef(pcrEntries(pcrs)))), base())
	{
		es := pcrEntries(pcrs)
		es[0].v = cBytesIndef(pcrs[0][:24], pcrs[0][24:])
		add("synthetic indefinite-length byte string in a PCR", doc(setField(fields, "pcrs", cMap(es))), base())
	}
	add("synthetic tag inside the payload (timestamp tag 1)", doc(setField(fields, "timestamp", cTag(1, cUint(uint64(tsMs))))), base())
	add("synthetic unknown extra payload field", doc(append(slices.Clone(fields), entry{cText("extra"), cUint(1)})), base())
	add("synthetic payload field name Nonce in other case", doc(renameField(fields, "nonce", "Nonce")), base())
	{
		es := pcrEntries(pcrs)
		for i := range es {
			es[i].k = cText(strconv.Itoa(i))
		}
		add("synthetic pcrs keys as text strings", doc(setField(fields, "pcrs", cMap(es))), base())
	}
	add("synthetic signed by the intermediate key", ca.cose(coseSpec{payload: good, signer: ca.interKey}), base())
	add("synthetic signature 95 bytes", ca.cose(coseSpec{payload: good, sig: make([]byte, 95)}), base())
	add("synthetic alg ES256 in the protected header", ca.cose(coseSpec{payload: good, protected: cMap([]entry{{cUint(1), cNeg(-7)}})}), base())
	add("synthetic alg as text ES384", ca.cose(coseSpec{payload: good, protected: cMap([]entry{{cUint(1), cText("ES384")}})}), base())
	add("synthetic protected header empty", ca.cose(coseSpec{payload: good, protected: []byte{}}), base())
	add("synthetic crit in the protected header", ca.cose(coseSpec{payload: good, protected: cMap([]entry{{cUint(1), cNeg(-35)}, {cUint(2), cArray(cUint(1))}})}), base())
	add("synthetic protected header with kid", ca.cose(coseSpec{payload: good, protected: cMap([]entry{{cUint(1), cNeg(-35)}, {cUint(4), cBytes([]byte("kid"))}})}), base())
	add("synthetic unprotected header null", ca.cose(coseSpec{payload: good, unprotected: cNull}), base())
	add("synthetic unprotected header an array", ca.cose(coseSpec{payload: good, unprotected: cArray()}), base())
	add("synthetic unprotected header with a kid", ca.cose(coseSpec{payload: good, unprotected: cMap([]entry{{cUint(4), cBytes([]byte("kid"))}})}), base())
	add("synthetic payload trailing bytes after the map", ca.cose(coseSpec{payload: append(slices.Clone(good), 0x00)}), base())
	add("synthetic payload as a text string", ca.cose(coseSpec{payload: good, payloadItem: cText(string(good))}), base())
	add("synthetic payload empty", ca.cose(coseSpec{payload: []byte{}}), base())
	add("synthetic payload null", ca.cose(coseSpec{payload: good, payloadItem: cNull}), base())
	add("synthetic trailing byte after the document", ca.cose(coseSpec{payload: good, trailing: []byte{0x00}}), base())
	add("synthetic trailing byte after a tagged document", ca.cose(coseSpec{payload: good, prefix: []byte{0xd2}, trailing: []byte{0x00}}), base())
	add("synthetic COSE array of 3 elements", ca.cose(coseSpec{payload: good, elems: 3}), base())
	add("synthetic empty document", []byte{}, base())
	{
		c := ca.cose(coseSpec{payload: good})
		add("synthetic flipped signature bit", flip(c, len(c)-1), base())
	}

	// Payload fields.
	add("synthetic missing pcr8", doc(pcrsWith(func(m map[uint64][]byte) { delete(m, 8) })), base())
	add("synthetic only pcr0 to pcr8", doc(pcrsWith(func(m map[uint64][]byte) {
		for i := uint64(9); i < 16; i++ {
			delete(m, i)
		}
	})), base())
	add("synthetic 32-byte PCR", doc(pcrsWith(func(m map[uint64][]byte) { m[5] = make([]byte, 32) })), base())
	add("synthetic pcr index 32", doc(pcrsWith(func(m map[uint64][]byte) { m[32] = make([]byte, 48) })), base())
	add("synthetic pcr index 31", doc(pcrsWith(func(m map[uint64][]byte) { m[31] = make([]byte, 48) })), base())
	add("synthetic digest SHA256", doc(setField(fields, "digest", cText("SHA256"))), base())
	add("synthetic digest sha384 lower case", doc(setField(fields, "digest", cText("sha384"))), base())
	add("synthetic timestamp 0", doc(setField(fields, "timestamp", cUint(0))), base())
	add("synthetic timestamp negative", doc(setField(fields, "timestamp", cNeg(-1000))), base())
	add("synthetic module_id empty", doc(setField(fields, "module_id", cText(""))), base())
	add("synthetic module_id missing", doc(dropField(fields, "module_id")), base())
	add("synthetic user_data null while expected", doc(setField(fields, "user_data", cNull)), base())
	add("synthetic user_data missing while expected", doc(dropField(fields, "user_data")), base())
	add("synthetic nonce null while expected", doc(setField(fields, "nonce", cNull)), base())
	add("synthetic nonce empty while expected", doc(setField(fields, "nonce", cBytes(nil))), base())
	add("synthetic public_key present", doc(setField(fields, "public_key", cBytes(sum256("enclave public key")))), base())
	{
		zero := pcrsWith(func(m map[uint64][]byte) {
			for i := uint64(0); i < 3; i++ {
				m[i] = make([]byte, 48)
			}
		})
		add("synthetic debug PCRs all zero", doc(zero), with(func(o *nitroOpts) {
			o.pcrs = map[int][]byte{0: make([]byte, 48), 1: make([]byte, 48), 2: make([]byte, 48)}
		}))
	}
	{
		changed := cMap(setField(fields, "user_data", cBytes(flip(ud, 0))))
		add("synthetic flipped byte in user data of the payload", ca.cose(coseSpec{payload: changed, signedPayload: good}), with(func(o *nitroOpts) { o.userData = nil }))
		m := defaultPCRs()
		m[1] = flip(m[1], 10)
		changedPCR := cMap(setField(fields, "pcrs", cMap(pcrEntries(m))))
		add("synthetic flipped byte inside PCR1 of the payload", ca.cose(coseSpec{payload: changedPCR, signedPayload: good}), with(pins(map[int][]byte{1: m[1]})))
	}

	// Chain.
	add("synthetic cabundle empty", doc(setField(fields, "cabundle", cArray())), base())
	add("synthetic cabundle[0] not the root", doc(setField(fields, "cabundle", cArray(cBytes(ca.inter.Raw), cBytes(ca.root.Raw)))), base())
	add("synthetic cabundle root only, no intermediate", doc(setField(fields, "cabundle", cArray(cBytes(ca.root.Raw)))), base())
	add("synthetic cabundle intermediate of another CA", doc(setField(fields, "cabundle", cArray(cBytes(ca.root.Raw), cBytes(other.inter.Raw)))), base())
	add("synthetic certificate empty", doc(setField(fields, "certificate", cBytes(nil))), base())
	add("synthetic certificate of another CA", doc(setField(fields, "certificate", cBytes(other.leaf.Raw))), base())
	add("synthetic roots null (pinned AWS root)", plain, with(func(o *nitroOpts) { o.roots = nil }))
	add("synthetic roots: another test CA", plain, with(func(o *nitroOpts) { o.roots = []*x509.Certificate{other.root} }))
	add("synthetic roots: both test CAs", plain, with(func(o *nitroOpts) { o.roots = []*x509.Certificate{other.root, ca.root} }))

	// Time.
	ts := func(d time.Duration) []byte {
		return doc(setField(fields, "timestamp", cUint(uint64(at.Add(d).UnixMilli()))))
	}
	add("synthetic timestamp 2 min in the future", ts(2*time.Minute), base())
	add("synthetic timestamp 60 s ahead (edge)", ts(60*time.Second), base())
	add("synthetic timestamp 60.001 s ahead", ts(60*time.Second+time.Millisecond), base())
	add("synthetic timestamp 50 min old (no max age)", ts(-50*time.Minute), base())
	add("synthetic verified one hour after its time (no max age)", plain, with(func(o *nitroOpts) { o.now = at.Add(time.Hour) }))
	add("synthetic verified 30 s before its time (within skew)", plain, with(func(o *nitroOpts) { o.now = at.Add(-30 * time.Second) }))
	add("synthetic verified 2 min before its time", plain, with(func(o *nitroOpts) { o.now = at.Add(-2 * time.Minute) }))
	{
		late := at.Add(3 * time.Hour)
		add("synthetic leaf expired at now", doc(setField(fields, "timestamp", cUint(uint64(late.UnixMilli())))), with(func(o *nitroOpts) { o.now = late }))
		add("synthetic leaf expired, document at its own time", plain, with(func(o *nitroOpts) { o.now = late }))
		early := at.Add(-2 * time.Hour)
		add("synthetic leaf not yet valid at now", doc(setField(fields, "timestamp", cUint(uint64(early.UnixMilli())))), with(func(o *nitroOpts) { o.now = early }))
	}

	// Expected values.
	add("synthetic wrong nonce", plain, with(func(o *nitroOpts) { o.nonce = sum256("other nonce") }))
	add("synthetic empty nonce while the document has one", plain, with(func(o *nitroOpts) { o.nonce = []byte{} }))
	add("synthetic wrong user data", plain, with(func(o *nitroOpts) { o.userData = sum256("other user data") }))
	add("synthetic nil nonce (config refusal)", plain, with(func(o *nitroOpts) { o.nonce = nil }))
	add("synthetic user data nil (not checked)", plain, with(func(o *nitroOpts) { o.userData = nil }))
	add("synthetic no expected PCRs (config refusal)", plain, with(func(o *nitroOpts) { o.pcrs = nil }))
	add("synthetic PCR8 pinned", plain, with(pins(map[int][]byte{8: pcrs[8]})))
	add("synthetic PCR3 pinned to the document's value", plain, with(pins(map[int][]byte{3: pcrs[3]})))
	add("synthetic PCR3 pinned to another value", plain, with(pins(map[int][]byte{3: fill(48, 0x33)})))
	add("synthetic PCR20 expected, not in the document", plain, with(pins(map[int][]byte{20: fill(48, 0x20)})))
	add("synthetic PCR9 pinned to zero", plain, with(pins(map[int][]byte{9: make([]byte, 48)})))
	add("synthetic wrong PCR0", plain, with(pins(map[int][]byte{0: fill(48, 0x10)})))
	add("synthetic wrong PCR1", plain, with(pins(map[int][]byte{1: fill(48, 0x11)})))
	add("synthetic wrong PCR2", plain, with(pins(map[int][]byte{2: fill(48, 0x12)})))
	add("synthetic expected PCR of 32 bytes", plain, with(pins(map[int][]byte{2: pcrs[2][:32]})))
	return cs
}
