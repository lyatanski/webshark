package main

// The ESP security associations of a capture, read out of the capture itself.
//
// Gm is protected with IPsec ESP in transport mode, and 3GPP keys it from AKA
// rather than from IKE (TS 33.203): the four SAs of one registration all take CK
// as their encryption key and IK as their integrity key, and their SPIs are
// agreed in the SIP headers of that same registration. So a capture that holds a
// registration holds everything its SAs need - spread over three of its
// messages, and no fewer:
//
//	REGISTER Gm  Security-Client: ...;spi-c=8193;spi-s=8194       what the UE receives on
//	401      Mw  WWW-Authenticate: ...,ck="46cc...",ik="06c1..."  the keys
//	401      Gm  Security-Server: ...;spi-c=256;spi-s=257         what the P-CSCF receives on
//
// The P-CSCF takes ck and ik out of the 401 before the UE sees it - that is the
// point of them travelling in it - so no single message carries both the keys and
// the SPIs they belong to. What relates the three is the Call-ID, the one field
// all of them have.
//
// The SPIs a party hands out are the ones it will receive on, which is what
// decides the direction of each record: the P-CSCF's SPIs (Security-Server) go on
// the frames sent to it, the UE's (Security-Client) on the frames sent back.
// Wireshark matches an SA by source, destination and SPI, so that is four
// records, and the pairs of SPIs both sides allocate are emitted whether or not
// traffic ever used both.
//
// Out comes Wireshark's own esp_sa syntax, the same lines its ESP SAs dialog
// writes:
//
//	"IPv4","10.10.0.2","192.168.69.70","0x00000101","NULL","","HMAC-SHA-1-96 [RFC2404]","0x06c1..."
//
// The server installs them into every sharkd it starts (sharkd.go), and
// `webshark -esp <capture>` prints them for everything else that reads an esp_sa
// file - tshark, dftest, Wireshark itself:
//
//	webshark -esp /captures/trace.pcapng > ~/.config/wireshark/esp_sa
//
// This reads them out of the sharkd that already holds the capture. `frames`
// takes a display filter and a column list, and a column can be any field, so
// the seven values below come back as seven columns of the few frames that carry
// them: one request, no second reading of the file and no second program.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Only the frames that hold one of the three headers, and of those only the
// columns below.
const espFilter = "sip.auth.ik || sip.Security-Server || sip.Security-Client"

// sharkd's `frames` takes a column list rather than a field list: `<display
// filter>:<occurrence>` is a custom column over that field, and a bare number is
// one of Wireshark's own column formats, given as its position in the COL_ enum
// of epan/column-utils.h.
//
// An occurrence of -1 is the last occurrence of the field in the frame, which is
// what `tshark -E occurrence=l` was for: where one TCP segment carries several
// SIP messages, the parameters of the last of them are then read together,
// instead of every message's being joined into one unusable value.
//
// The addresses are columns rather than ip.src and ip.dst because a column holds
// the address of the innermost header - which is the pair ESP is matched on, and
// in this stack is inside a GTP-U tunnel whose own addresses are of no interest.
// It is also the only spelling that does not have to know in advance whether the
// registration is over IPv4 or IPv6, or which of the two is carrying the other.
// Unresolved rather than the default pair, which is what `tshark -n` was for: a
// profile with nameres.network_name on would otherwise put a host name there.
var espColumns = []string{
	"41", "8", // COL_UNRES_SRC, COL_UNRES_DST
	"sip.Call-ID:-1",
	"sip.auth.ck:-1",
	"sip.auth.ik:-1",
	"sip.Security-Server:-1",
	"sip.Security-Client:-1",
}

// ...in that order, which is how a row is read.
const (
	espSrc = iota
	espDst
	espCall
	espCK
	espIK
	espServer
	espClient
)

// The mechanism parameters of TS 33.203 Annex H, in Wireshark's spelling of the
// same algorithms. Nothing outside these tables is guessed at: an unknown ealg
// means the payload cannot be decoded at all and the SA is dropped, while an
// unknown alg costs only the integrity check, so ESP is told the one thing both
// 3GPP algorithms agree on - a 96-bit ICV - and left to find the payload.
var (
	espEncr = map[string]string{
		"null":         "NULL",
		"aes-cbc":      "AES-CBC [RFC3602]",
		"des-ede3-cbc": "TripleDES-CBC [RFC2451]",
	}
	espAuth = map[string]string{
		"hmac-md5-96":   "HMAC-MD5-96 [RFC2403]",
		"hmac-sha-1-96": "HMAC-SHA-1-96 [RFC2404]",
	}
)

const espAnyICV = "ANY 96 bit authentication [no checking]"

// espSAs asks one loaded capture's sharkd for its SAs and returns them as esp_sa
// records, deduplicated, in the order the registrations that produced them
// appear in the file. No SAs is not an error: most captures have no IPsec in
// them at all.
func espSAs(s *session) ([]string, error) {
	params := map[string]any{"filter": espFilter}
	for i, column := range espColumns {
		params["column"+strconv.Itoa(i)] = column
	}
	// No `limit`, which sharkd reads as no limit at all, so this is every frame
	// the filter passes - and the filter has already cut the file down to the
	// few frames of its registrations.
	raw, err := s.do("frames", params)
	if err != nil {
		return nil, err
	}
	var frames []struct {
		Columns []string `json:"c"`
	}
	if err := json.Unmarshal(raw, &frames); err != nil {
		return nil, fmt.Errorf("esp: %w", err)
	}

	// Both maps are the state of a registration in progress, keyed by Call-ID:
	// the keys of the last challenge seen in it, and the SPIs the UE asked for.
	// Both are overwritten rather than appended to, so a registration challenged
	// twice - new keys, new SPIs - keeps the SAs of its earlier attempt and adds
	// the ones of the later.
	keys := map[string][2]string{}
	client := map[string][]string{}

	var sas []string
	seen := map[string]bool{}
	for _, frame := range frames {
		row := espRow(frame.Columns)
		call := row[espCall]
		if call == "" {
			continue
		}

		// Keyed on IK, which every SA needs; CK is only wanted by an encrypted
		// one, and a 401 that carries no IK at all is not a challenge.
		if ik := espHex(row[espIK]); ik != "" {
			keys[call] = [2]string{espHex(row[espCK]), ik}
		}
		if header := row[espClient]; header != "" {
			if spis := espSPIs(espMech(header)); len(spis) > 0 {
				client[call] = spis
			}
		}

		// Everything comes together on the 401 that carries Security-Server:
		// it is the last of the three messages, and the only one that says
		// which addresses the SAs are between.
		header := row[espServer]
		if header == "" {
			continue
		}
		// The addresses are parsed rather than trusted, which is also where the
		// address family comes from: the two column numbers above are positions
		// in an enum upstream keeps in alphabetical order, so an entry added to
		// it moves them, and a column that stops holding an address is then a
		// row dropped rather than an SA built out of a protocol name.
		pcscf, ue := row[espSrc], row[espDst]
		src, err := netip.ParseAddr(pcscf)
		if err != nil {
			continue
		}
		if _, err := netip.ParseAddr(ue); err != nil {
			continue
		}
		proto := "IPv4"
		if src.Is6() {
			proto = "IPv6"
		}
		mech := espMech(header)
		ck, ik := keys[call][0], keys[call][1]
		enc, encOK := espEncr[mech["ealg"]]
		auth, authOK := espAuth[mech["alg"]]
		if !authOK {
			auth = espAnyICV
		}
		// Everything the four records are still made of, the addresses now being
		// behind us: a challenge to take the keys from, an encryption algorithm
		// that can be named at all, and ESP rather than the AH nobody deploys.
		if ik == "" || !encOK || mech["prot"] == "ah" || (enc != "NULL" && ck == "") {
			continue
		}

		add := func(src, dst string, spis []string) {
			for _, spi := range spis {
				record := fmt.Sprintf("%q,%q,%q,%q,%q,%q,%q,%q", proto, src, dst, spi,
					enc, espEncrKey(mech["ealg"], ck), auth, espAuthKey(mech["alg"], ik))
				if !seen[record] {
					seen[record] = true
					sas = append(sas, record)
				}
			}
		}
		add(ue, pcscf, espSPIs(mech))
		add(pcscf, ue, client[call])
	}
	return sas, nil
}

// espFile is `webshark -esp <capture>`: the SAs of one capture named by path,
// out of a sharkd started to hold it and nothing else. A bare pool because
// start() wants no more than the binary to run - there is nothing here to pool.
func espFile(bin, path string) ([]string, error) {
	s, err := (&pool{bin: bin}).start()
	if err != nil {
		return nil, err
	}
	defer s.close()
	if _, err := s.do("load", map[string]any{"file": path}); err != nil {
		return nil, err
	}
	return espSAs(s)
}

// A row is one frame's columns, in the order of espColumns above, the absent
// ones empty. It is padded rather than rejected, so a sharkd that answers with
// fewer columns than it was asked for cannot index out of range here.
func espRow(columns []string) []string {
	row := make([]string, len(espColumns))
	copy(row, columns)
	return row
}

// One security-agreement header value as the parameters of the one mechanism in
// it the SAs are made of.
//
// RFC 3329 makes the value a list of mechanisms and not a single one -
// `ipsec-3gpp;q=0.1;prot=esp;spi-c=256;…, digest;d-alg=md5` - separated by
// commas, each of them `name` followed by its own `;param=value`. A UE that
// supports several algorithm pairs offers one mechanism per pair, so four of
// them in one header is ordinary, and every one of the four repeats the same
// SPIs: what a party allocates is one pair of SAs, whatever is agreed to run
// over it.
//
// So the mechanisms are separated first and only then their parameters, which is
// the whole of the fix this once needed: splitting the value on `;` alone left
// the last parameter of each mechanism carrying the next one's name -
// `spi-s=208007319,ipsec-3gpp` - which is not a number, and filled in whatever
// the first mechanism did not have from the ones after it, which is a mechanism
// no party offered.
//
// The one read is the first that names an SPI, so a header leading with a
// mechanism that is not IPsec at all is stepped over rather than read as the
// answer. Where a Security-Server offers several, RFC 3329 has both ends take
// the one with the highest `q` and this takes the first, which differs only for
// a P-CSCF that answers with more than the mechanism it chose. Within a
// mechanism the first occurrence of a parameter wins, and values are lowercased
// because the algorithm names above are compared against.
func espMech(header string) map[string]string {
	for _, mechanism := range strings.Split(header, ",") {
		mech := map[string]string{}
		// the mechanism name is the part before the first `;` and has no `=` in
		// it, so it falls out of the loop below on its own
		for _, part := range strings.Split(mechanism, ";") {
			name, value, ok := strings.Cut(part, "=")
			if !ok {
				continue
			}
			name = strings.ToLower(strings.TrimSpace(name))
			if _, dup := mech[name]; !dup {
				mech[name] = strings.ToLower(strings.TrimSpace(value))
			}
		}
		if len(espSPIs(mech)) > 0 {
			return mech
		}
	}
	return nil
}

// The two SPIs of one mechanism, as the SA table spells an SPI. RFC 3329 writes
// them in decimal; a party that offered only one of them gets one record.
func espSPIs(mech map[string]string) []string {
	var spis []string
	for _, name := range []string{"spi-c", "spi-s"} {
		if n, err := strconv.ParseUint(mech[name], 10, 32); err == nil {
			spis = append(spis, fmt.Sprintf("0x%08x", n))
		}
	}
	return spis
}

// ck="46ccd0dad7d0ac0d781c8415c1a0243b" -> 46ccd0dad7d0ac0d781c8415c1a0243b.
// The quotes are part of the field, the header having them. Anything that is not
// a 128-bit hex string is not a CK or an IK and is dropped: both are 128 bits in
// every AKA vector, and a key of another length would be a wrong guess about
// what the parameter holds rather than a longer key.
func espHex(value string) string {
	value = strings.ToLower(strings.Trim(value, `"`))
	if len(value) != 32 {
		return ""
	}
	for _, c := range value {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return ""
		}
	}
	return value
}

// TS 33.203 Annex I: ESP takes the AKA keys as they are where the lengths agree,
// and expands them where they do not. Both keys are 128 bits.
//
// The IK padding is a formality as far as Wireshark is concerned, HMAC padding a
// short key with zeros itself, so the MAC over IK and over IK||0…0 is the same
// one - but it is what the kernel's SA holds, and the 3DES expansion is not a
// formality at all: the wrong length there is refused outright.
func espAuthKey(alg, ik string) string {
	if alg == "hmac-sha-1-96" { // 160 bits wanted: IK || 32 zero bits
		return "0x" + ik + "00000000"
	}
	return "0x" + ik // hmac-md5-96 wants the 128 bits IK already is
}

func espEncrKey(ealg, ck string) string {
	switch ealg {
	case "null": // nothing is encrypted, so there is no key to hold
		return ""
	case "des-ede3-cbc": // 192 bits wanted: CK || the 64 most significant bits of CK
		return "0x" + ck + ck[:16]
	}
	return "0x" + ck // aes-cbc wants the 128 bits CK already is
}
