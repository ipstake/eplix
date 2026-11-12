package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"slices"
	"strconv"
	"time"

	attest "github.com/lidofinance/tee-signer/attestation-verify"
)

// testCA is a three-level ECDSA P-384 chain shaped like the AWS Nitro one: root, zonal
// intermediate, short-lived leaf that signs the documents.
type testCA struct {
	root, inter, leaf          *x509.Certificate
	rootKey, interKey, leafKey *ecdsa.PrivateKey
}

func newKey384() *ecdsa.PrivateKey { return must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader)) }

func makeCert(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	der := must(x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer))
	return must(x509.ParseCertificate(der))
}

// newCA makes a chain valid around at. The leaf lives from one hour before at to two hours
// after it, close to the three hours of a real Nitro leaf.
func newCA(name string, at time.Time) *testCA {
	ca := &testCA{rootKey: newKey384(), interKey: newKey384(), leafKey: newKey384()}
	caTmpl := func(cn string, serial int64) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn, Organization: []string{name}},
			NotBefore:             at.Add(-24 * time.Hour),
			NotAfter:              at.Add(365 * 24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		}
	}
	rt := caTmpl("test.nitro-enclaves", 1)
	ca.root = makeCert(rt, rt, &ca.rootKey.PublicKey, ca.rootKey)
	ca.inter = makeCert(caTmpl("test-zonal", 2), ca.root, &ca.interKey.PublicKey, ca.rootKey)
	lt := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "i-00000000000000000-enc0000000000000000", Organization: []string{name}},
		NotBefore:    at.Add(-time.Hour),
		NotAfter:     at.Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	ca.leaf = makeCert(lt, ca.inter, &ca.leafKey.PublicKey, ca.interKey)
	return ca
}

func pemOf(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// defaultPCRs are PCR0 to PCR15 as a document from a signed image with an IAM role has them:
// PCR0 to PCR4 and PCR8 set (bytes 0xa0+i), the rest zero.
func defaultPCRs() map[uint64][]byte {
	m := map[uint64][]byte{}
	for i := uint64(0); i < 16; i++ {
		m[i] = make([]byte, 48)
	}
	for _, i := range []uint64{0, 1, 2, 3, 4, 8} {
		m[i] = fill(48, 0xa0+byte(i))
	}
	return m
}

func pcrEntries(m map[uint64][]byte) []entry {
	keys := make([]uint64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	es := make([]entry, 0, len(keys))
	for _, k := range keys {
		es = append(es, entry{cUint(k), cBytes(m[k])})
	}
	return es
}

func nullable(b []byte) []byte {
	if b == nil {
		return cNull
	}
	return cBytes(b)
}

// payload is the NSM document payload in the order AWS writes it.
func (ca *testCA) payload(tsMs int64, pcrs []entry, nonce, userData []byte) []entry {
	return []entry{
		{cText("module_id"), cText("i-00000000000000000-enc0000000000000000")},
		{cText("digest"), cText("SHA384")},
		{cText("timestamp"), cUint(uint64(tsMs))},
		{cText("pcrs"), cMap(pcrs)},
		{cText("certificate"), cBytes(ca.leaf.Raw)},
		{cText("cabundle"), cArray(cBytes(ca.root.Raw), cBytes(ca.inter.Raw))},
		{cText("public_key"), cNull},
		{cText("user_data"), nullable(userData)},
		{cText("nonce"), nullable(nonce)},
	}
}

func setField(es []entry, name string, v []byte) []entry {
	out := slices.Clone(es)
	for i := range out {
		if bytes.Equal(out[i].k, cText(name)) {
			out[i].v = v
		}
	}
	return out
}

func dropField(es []entry, name string) []entry {
	return slices.DeleteFunc(slices.Clone(es), func(e entry) bool { return bytes.Equal(e.k, cText(name)) })
}

func renameField(es []entry, from, to string) []entry {
	out := slices.Clone(es)
	for i := range out {
		if bytes.Equal(out[i].k, cText(from)) {
			out[i].k = cText(to)
		}
	}
	return out
}

// coseSpec describes a COSE_Sign1 document. Zero fields take the layout of a real document:
// protected header {1: -35} (ES384), empty unprotected header, signature by the leaf key over
// the payload, four elements, no tag.
type coseSpec struct {
	protected     []byte // encoded header map
	unprotected   []byte // encoded item
	payload       []byte // payload bytes (the content of the byte string)
	payloadItem   []byte // if set, the third element as is
	signedPayload []byte // if set, the signature covers this instead of payload
	signer        *ecdsa.PrivateKey
	sig           []byte // if set, the signature as is
	elems         int    // 3 leaves the signature out
	indefOuter    bool
	prefix        []byte // tags before the array
	trailing      []byte
}

func (ca *testCA) cose(s coseSpec) []byte {
	if s.protected == nil {
		s.protected = cMap([]entry{{cUint(1), cNeg(-35)}})
	}
	if s.unprotected == nil {
		s.unprotected = cMap(nil)
	}
	if s.signer == nil {
		s.signer = ca.leafKey
	}
	signed := s.payload
	if s.signedPayload != nil {
		signed = s.signedPayload
	}
	sig := s.sig
	if sig == nil {
		tbs := cArray(cText("Signature1"), cBytes(s.protected), cBytes(nil), cBytes(signed))
		h := sha512.Sum384(tbs)
		r, sv := must2(ecdsa.Sign(rand.Reader, s.signer, h[:]))
		sig = make([]byte, 96)
		r.FillBytes(sig[:48])
		sv.FillBytes(sig[48:])
	}
	item := s.payloadItem
	if item == nil {
		item = cBytes(s.payload)
	}
	elems := [][]byte{cBytes(s.protected), s.unprotected, item, cBytes(sig)}
	if s.elems == 3 {
		elems = elems[:3]
	}
	var doc []byte
	if s.indefOuter {
		doc = cArrayIndef(elems...)
	} else {
		doc = cArray(elems...)
	}
	return append(append(slices.Clone(s.prefix), doc...), s.trailing...)
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		fail(err)
	}
	return a, b
}

// nitroOpts are the verifier options of one case. A nil roots list means the AWS root that
// attest pins.
type nitroOpts struct {
	roots    []*x509.Certificate
	pcrs     map[int][]byte
	nonce    []byte
	userData []byte
	now      time.Time
}

func (g *gen) nitroCase(name string, doc []byte, o nitroOpts) nitroCase {
	c := nitroCase{Name: name, Document: hex.EncodeToString(doc), NowMs: o.now.UnixMilli(),
		Nonce: hexPtr(o.nonce), UserData: hexPtr(o.userData)}
	for _, r := range o.roots {
		c.RootsPEM = append(c.RootsPEM, pemOf(r))
	}
	if o.pcrs != nil {
		c.PCRs = map[string]string{}
		for i, v := range o.pcrs {
			c.PCRs[strconv.Itoa(i)] = hex.EncodeToString(v)
		}
	}
	_, err := attest.VerifyNitro(doc, attest.NitroOptions{Roots: o.roots, Now: o.now, PCRs: o.pcrs, Nonce: o.nonce, UserData: o.userData})
	c.Expect, c.Error = verdict(err)
	return c
}

func verdict(err error) (string, string) {
	if err != nil {
		return "fail", err.Error()
	}
	return "ok", ""
}
