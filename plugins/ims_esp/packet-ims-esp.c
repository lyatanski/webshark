/* packet-ims-esp.c
 *
 * The ESP security associations of a capture, recovered from the capture itself.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Gm is protected with IPsec ESP in transport mode, and 3GPP keys it from AKA
 * rather than from IKE (TS 33.203): the four SAs of one registration all take CK
 * as their encryption key and IK as their integrity key, and their SPIs are
 * agreed in the SIP headers of that same registration. So a capture that holds a
 * registration holds everything its SAs need - spread over three of its
 * messages, and no fewer:
 *
 *	REGISTER Gm  Security-Client: ...;spi-c=8193;spi-s=8194       what the UE receives on
 *	401      Mw  WWW-Authenticate: ...,ck="46cc...",ik="06c1..."  the keys
 *	401      Gm  Security-Server: ...;spi-c=256;spi-s=257         what the P-CSCF receives on
 *
 * The P-CSCF takes ck and ik out of the 401 before the UE sees it - that is the
 * point of them travelling in it - so no single message carries both the keys and
 * the SPIs they belong to. What relates the three is the Call-ID, the one field
 * all of them have.
 *
 * The SPIs a party hands out are the ones it will receive on, which is what
 * decides the direction of each record: the P-CSCF's SPIs (Security-Server) go on
 * the frames sent to it, the UE's (Security-Client) on the frames sent back.
 * Wireshark matches an SA by source, destination and SPI, so that is four
 * records, and the pairs of SPIs both sides allocate are emitted whether or not
 * traffic ever used both.
 *
 * The records go into the same "ESP SAs" table that Wireshark's ESP SAs dialog
 * writes, in the same syntax an esp_sa file holds:
 *
 *	"IPv4","10.10.0.2","192.168.69.70","0x00000101","NULL","","HMAC-SHA-1-96 [RFC2404]","0x06c1..."
 *
 * so from the ESP dissector's point of view nothing distinguishes them from SAs
 * a user typed in, and every program that loads this plugin - sharkd, tshark,
 * Wireshark itself - dissects protected Gm with no configuration and no second
 * reading of the file.
 *
 * ---------------------------------------------------------------------------
 *
 * This is a postdissector, and the SIP headers reach it as field values rather
 * than as text it parses itself: set_postdissector_wanted_hfids() below asks
 * epan for the five fields the SAs are made of, which is what makes them
 * available on the first pass over the file even when nothing else has asked
 * for a dissection tree.
 *
 * That first pass is the whole reason a postdissector is the right shape for
 * this. Frames are dissected in file order, a registration precedes the traffic
 * it protects, and an SA installed while the 401 is being dissected is
 * therefore in the table before the first frame that needs it. The keys are
 * found during the same read of the file that finds the registration, and
 * nothing has to be told to go looking for them.
 *
 * Deriving is confined to that pass on purpose - epan primes the wanted fields
 * only while frame_data.visited is false, and proto_get_finfo_ptr_array()
 * answers for primed fields alone - so a later dissection of the same frame
 * does no parsing at all. It is also the pass whose tree is thrown away, so
 * what a frame produced is kept on the frame as proto data and the ims_esp.sa
 * items are added from that, on this pass and every later one alike.
 */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/proto_data.h>
#include <epan/to_str.h>
#include <epan/uat.h>
#include <wsutil/strtoi.h>
#include <wsutil/wslog.h>

void proto_register_ims_esp(void);
void proto_reg_handoff_ims_esp(void);

static int proto_ims_esp;
static int hf_ims_esp_sa;
static int ett_ims_esp;

static dissector_handle_t ims_esp_handle;

/* Whether to do any of this. Turned off in a program that applies preferences
 * properly - Wireshark, or tshark -o - this also drops the wanted hfids below,
 * and with them the tree the first pass would otherwise have to build. */
static bool ims_esp_derive_sa = true;

/* The five SIP fields the SAs are made of, resolved by name at handoff because
 * they belong to a dissector this plugin does not build against. */
static int hf_sip_call_id = -1;
static int hf_sip_auth_ck = -1;
static int hf_sip_auth_ik = -1;
static int hf_sip_security_server = -1;
static int hf_sip_security_client = -1;

/* The state of a registration in progress, keyed by Call-ID and reset with the
 * file: the keys of the last challenge seen in it, and the SPIs the UE asked
 * for. Both are overwritten rather than appended to, so a registration
 * challenged twice - new keys, new SPIs - keeps the SAs of its earlier attempt
 * and adds the ones of the later. */
static wmem_map_t *ims_esp_keys;
static wmem_map_t *ims_esp_client;

/* Records already in the table, so that a registration repeated in the file, or
 * a file read twice, does not add the same SA twice. This one is *not* reset
 * with the file, because what it guards against duplicating - the "ESP SAs"
 * table - is not reset either. */
static wmem_map_t *ims_esp_installed;

typedef struct {
	const char *ck;
	const char *ik;
} ims_esp_keys_t;

/* The two SPIs one party allocated, as the SA table spells an SPI, absent ones
 * NULL. */
typedef struct {
	const char *spi_c;
	const char *spi_s;
} ims_esp_spis_t;

/* One mechanism of a security-agreement header, its parameters as written. */
typedef struct {
	const char *prot;
	const char *ealg;
	const char *alg;
	const char *spi_c;
	const char *spi_s;
} ims_esp_mech_t;

/* The mechanism parameters of TS 33.203 Annex H, in the SA table's spelling of
 * the same algorithms. Nothing outside these tables is guessed at: an unknown
 * ealg means the payload cannot be decoded at all and the SA is dropped, while
 * an unknown alg costs only the integrity check, so ESP is told the one thing
 * both 3GPP algorithms agree on - a 96-bit ICV - and left to find the payload. */
typedef struct { const char *mech; const char *sa; } ims_esp_algo_t;

static const ims_esp_algo_t ims_esp_encr[] = {
	{ "null",         "NULL" },
	{ "aes-cbc",      "AES-CBC [RFC3602]" },
	{ "des-ede3-cbc", "TripleDES-CBC [RFC2451]" },
};

static const ims_esp_algo_t ims_esp_auth[] = {
	{ "hmac-md5-96",   "HMAC-MD5-96 [RFC2403]" },
	{ "hmac-sha-1-96", "HMAC-SHA-1-96 [RFC2404]" },
};

#define IMS_ESP_ANY_ICV "ANY 96 bit authentication [no checking]"

static const char *
ims_esp_algo(const ims_esp_algo_t *table, size_t len, const char *mech)
{
	size_t i;

	if (mech == NULL)
		return NULL;
	for (i = 0; i < len; i++) {
		if (strcmp(table[i].mech, mech) == 0)
			return table[i].sa;
	}
	return NULL;
}

/* The last occurrence of one field in the frame, or NULL.
 *
 * The last, rather than the first, because where one TCP segment carries several
 * SIP messages every one of them contributes an occurrence: reading the last of
 * each field takes the parameters of the last message together, rather than
 * pairing the keys of one message with the SPIs of another.
 *
 * Primed fields only, which is what confines this to the first pass. The array
 * belongs to the tree and must not be freed. */
static const char *
ims_esp_field(proto_tree *tree, int hfid)
{
	GPtrArray *finfos;
	field_info *fi;

	if (hfid <= 0)
		return NULL;
	finfos = proto_get_finfo_ptr_array(tree, hfid);
	if (finfos == NULL || finfos->len == 0)
		return NULL;
	fi = (field_info *)g_ptr_array_index(finfos, finfos->len - 1);
	return fvalue_get_string(fi->value);
}

/* A trimmed, lowercased copy of one token. The algorithm names above are
 * compared against it, and RFC 3329 does not say what case a parameter is
 * written in. */
static char *
ims_esp_token(wmem_allocator_t *scope, const char *start, const char *end)
{
	char *out;
	size_t i, len;

	while (start < end && g_ascii_isspace(*start))
		start++;
	while (end > start && g_ascii_isspace(end[-1]))
		end--;
	len = (size_t)(end - start);
	out = (char *)wmem_alloc(scope, len + 1);
	for (i = 0; i < len; i++)
		out[i] = g_ascii_tolower(start[i]);
	out[len] = '\0';
	return out;
}

/* Within a mechanism the first occurrence of a parameter wins. */
static void
ims_esp_mech_set(ims_esp_mech_t *mech, const char *name, const char *value)
{
	if (strcmp(name, "prot") == 0) {
		if (mech->prot == NULL)
			mech->prot = value;
	} else if (strcmp(name, "ealg") == 0) {
		if (mech->ealg == NULL)
			mech->ealg = value;
	} else if (strcmp(name, "alg") == 0) {
		if (mech->alg == NULL)
			mech->alg = value;
	} else if (strcmp(name, "spi-c") == 0) {
		if (mech->spi_c == NULL)
			mech->spi_c = value;
	} else if (strcmp(name, "spi-s") == 0) {
		if (mech->spi_s == NULL)
			mech->spi_s = value;
	}
}

/* The SPIs of one mechanism, as the SA table spells an SPI. RFC 3329 writes them
 * in decimal; a party that offered only one of them gets one record. */
static unsigned
ims_esp_spis(const ims_esp_mech_t *mech, wmem_allocator_t *scope, ims_esp_spis_t *out)
{
	const char *raw[2];
	const char **spi[2];
	unsigned found = 0;
	unsigned i;

	out->spi_c = out->spi_s = NULL;
	raw[0] = mech->spi_c; spi[0] = &out->spi_c;
	raw[1] = mech->spi_s; spi[1] = &out->spi_s;

	for (i = 0; i < 2; i++) {
		uint32_t value;

		if (raw[i] == NULL || !ws_strtou32(raw[i], NULL, &value))
			continue;
		*spi[i] = wmem_strdup_printf(scope, "0x%08x", value);
		found++;
	}
	return found;
}

/* One security-agreement header value as the parameters of the one mechanism in
 * it the SAs are made of.
 *
 * RFC 3329 makes the value a list of mechanisms and not a single one -
 * `ipsec-3gpp;q=0.1;prot=esp;spi-c=256;..., digest;d-alg=md5` - separated by
 * commas, each of them `name` followed by its own `;param=value`. A UE that
 * supports several algorithm pairs offers one mechanism per pair, so four of
 * them in one header is ordinary, and every one of the four repeats the same
 * SPIs: what a party allocates is one pair of SAs, whatever is agreed to run
 * over it.
 *
 * So the mechanisms are separated first and only then their parameters.
 * Splitting the value on `;` alone would leave the last parameter of each
 * mechanism carrying the next one's name - `spi-s=208007319,ipsec-3gpp` - which
 * is not a number, and would fill in whatever the first mechanism did not have
 * from the ones after it, which is a mechanism no party offered.
 *
 * The one read is the first that names an SPI, so a header leading with a
 * mechanism that is not IPsec at all is stepped over rather than read as the
 * answer. Where a Security-Server offers several, RFC 3329 has both ends take
 * the one with the highest `q` and this takes the first, which differs only for
 * a P-CSCF that answers with more than the mechanism it chose. */
static bool
ims_esp_mech(const char *header, wmem_allocator_t *scope, ims_esp_mech_t *out,
	     ims_esp_spis_t *spis)
{
	const char *mech_start = header;

	while (*mech_start != '\0') {
		ims_esp_mech_t mech = { NULL, NULL, NULL, NULL, NULL };
		const char *mech_end = strchr(mech_start, ',');
		const char *part;

		if (mech_end == NULL)
			mech_end = mech_start + strlen(mech_start);

		part = mech_start;
		while (part < mech_end) {
			const char *part_end = (const char *)memchr(part, ';', (size_t)(mech_end - part));
			const char *eq;

			if (part_end == NULL)
				part_end = mech_end;
			/* the mechanism name is the part before the first `;` and
			 * has no `=` in it, so it falls out here on its own */
			eq = (const char *)memchr(part, '=', (size_t)(part_end - part));
			if (eq != NULL)
				ims_esp_mech_set(&mech, ims_esp_token(scope, part, eq),
						 ims_esp_token(scope, eq + 1, part_end));
			part = (part_end < mech_end) ? part_end + 1 : mech_end;
		}

		if (ims_esp_spis(&mech, scope, spis) > 0) {
			*out = mech;
			return true;
		}
		mech_start = (*mech_end == ',') ? mech_end + 1 : mech_end;
	}
	return false;
}

/* ck="46ccd0dad7d0ac0d781c8415c1a0243b" -> 46ccd0dad7d0ac0d781c8415c1a0243b.
 * The quotes are part of the field, the header having them. Anything that is not
 * a 128-bit hex string is not a CK or an IK and is dropped: both are 128 bits in
 * every AKA vector, and a key of another length would be a wrong guess about
 * what the parameter holds rather than a longer key. */
static const char *
ims_esp_hex(wmem_allocator_t *scope, const char *value)
{
	char *out;
	size_t i, len;

	if (value == NULL)
		return NULL;
	if (*value == '"')
		value++;
	len = strlen(value);
	if (len > 0 && value[len - 1] == '"')
		len--;
	if (len != 32)
		return NULL;

	out = (char *)wmem_alloc(scope, len + 1);
	for (i = 0; i < len; i++) {
		if (!g_ascii_isxdigit(value[i]))
			return NULL;
		out[i] = g_ascii_tolower(value[i]);
	}
	out[len] = '\0';
	return out;
}

/* TS 33.203 Annex I: ESP takes the AKA keys as they are where the lengths agree,
 * and expands them where they do not. Both keys are 128 bits.
 *
 * The IK padding is a formality as far as Wireshark is concerned, HMAC padding a
 * short key with zeros itself, so the MAC over IK and over IK||0...0 is the same
 * one - but it is what the kernel's SA holds, and the 3DES expansion is not a
 * formality at all: the wrong length there is refused outright. */
static const char *
ims_esp_auth_key(wmem_allocator_t *scope, const char *alg, const char *ik)
{
	if (g_strcmp0(alg, "hmac-sha-1-96") == 0) /* 160 bits wanted: IK || 32 zero bits */
		return wmem_strdup_printf(scope, "0x%s00000000", ik);
	return wmem_strdup_printf(scope, "0x%s", ik); /* hmac-md5-96 wants the 128 bits IK already is */
}

static const char *
ims_esp_encr_key(wmem_allocator_t *scope, const char *ealg, const char *ck)
{
	if (g_strcmp0(ealg, "null") == 0) /* nothing is encrypted, so there is no key to hold */
		return "";
	if (g_strcmp0(ealg, "des-ede3-cbc") == 0) /* 192 bits: CK || the 64 most significant bits of CK */
		return wmem_strdup_printf(scope, "0x%s%.16s", ck, ck);
	return wmem_strdup_printf(scope, "0x%s", ck); /* aes-cbc wants the 128 bits CK already is */
}

/* One record into the "ESP SAs" table.
 *
 * The table is reached by name because it belongs to the ESP dissector, and
 * uat_load_str() parses the record exactly as loading an esp_sa file or passing
 * `-o uat:esp_sa:...` would - so a record this plugin gets wrong is refused
 * there rather than acted on here. "ESP SAs" is the table's name and `esp_sa`
 * only the file it is stored in; uat_get_table_by_name() wants the former.
 *
 * Not esp_sa_record_add_from_dissector(), which is the interface packet-ipsec.h
 * offers for exactly this and would otherwise be the obvious choice: it holds
 * at most MAX_EXTRA_SA_RECORDS records, 16 of them, and calls
 * REPORT_DISSECTOR_BUG on the one after that. Four records to a registration
 * makes that four registrations to a capture, which no real Gm trace stays
 * under. The table this writes to instead grows.
 *
 * What that costs is a table that outlives the file, since only a file's own
 * ESP dissector state is reset with it - so the records are deduplicated
 * process-wide above, and a second capture in one process adds to what the
 * first one left. Harmless where an SA is matched on addresses and an SPI, and
 * it is what the Go code this replaces did too, one sharkd to a capture. */
static void
ims_esp_install(const char *record)
{
	uat_t *esp_uat;
	char *copy, *err = NULL;

	if (wmem_map_lookup(ims_esp_installed, record) != NULL)
		return;
	esp_uat = uat_get_table_by_name("ESP SAs");
	if (esp_uat == NULL)
		return; /* no ESP dissector to tell, so nothing to tell it */

	copy = wmem_strdup(wmem_epan_scope(), record);
	if (!uat_load_str(esp_uat, copy, &err)) {
		ws_warning("ims_esp: %s: %s", record, err != NULL ? err : "rejected");
		g_free(err);
		return;
	}
	wmem_map_insert(ims_esp_installed, copy, copy);
	/* Off by default; WIRESHARK_LOG_LEVEL=info to see what a capture gave up. */
	ws_info("ims_esp: %s", record);
}

/* Everything one frame contributes, derived once and remembered on the frame.
 *
 * Called only while the frame is unvisited, so each of the three messages of a
 * registration is read exactly once, in file order. */
static void
ims_esp_derive(packet_info *pinfo, proto_tree *tree)
{
	const char *call, *header, *ck, *ik, *pcscf, *ue, *proto, *enc, *auth;
	const char *directions[2][2];
	ims_esp_keys_t *keys;
	ims_esp_spis_t *client, offered;
	ims_esp_mech_t mech;
	wmem_array_t *records;
	unsigned direction;

	call = ims_esp_field(tree, hf_sip_call_id);
	if (call == NULL || *call == '\0')
		return;

	/* Keyed on IK, which every SA needs; CK is only wanted by an encrypted
	 * one, and a 401 that carries no IK at all is not a challenge. */
	ik = ims_esp_hex(pinfo->pool, ims_esp_field(tree, hf_sip_auth_ik));
	if (ik != NULL) {
		keys = wmem_new(wmem_file_scope(), ims_esp_keys_t);
		keys->ik = wmem_strdup(wmem_file_scope(), ik);
		ck = ims_esp_hex(pinfo->pool, ims_esp_field(tree, hf_sip_auth_ck));
		keys->ck = ck != NULL ? wmem_strdup(wmem_file_scope(), ck) : NULL;
		wmem_map_insert(ims_esp_keys, wmem_strdup(wmem_file_scope(), call), keys);
	}

	header = ims_esp_field(tree, hf_sip_security_client);
	if (header != NULL && ims_esp_mech(header, pinfo->pool, &mech, &offered)) {
		client = wmem_new(wmem_file_scope(), ims_esp_spis_t);
		client->spi_c = offered.spi_c != NULL ? wmem_strdup(wmem_file_scope(), offered.spi_c) : NULL;
		client->spi_s = offered.spi_s != NULL ? wmem_strdup(wmem_file_scope(), offered.spi_s) : NULL;
		wmem_map_insert(ims_esp_client, wmem_strdup(wmem_file_scope(), call), client);
	}

	/* Everything comes together on the 401 that carries Security-Server: it is
	 * the last of the three messages, and the only one that says which
	 * addresses the SAs are between. `mech` is that header's, so the algorithms
	 * below are the ones the P-CSCF chose rather than any the UE offered. */
	header = ims_esp_field(tree, hf_sip_security_server);
	if (header == NULL || !ims_esp_mech(header, pinfo->pool, &mech, &offered))
		return;

	/* The addresses, and the address family, taken the way the ESP dissector
	 * itself takes them - address_to_str() over pinfo->src and pinfo->dst,
	 * whose type decides IPv4 from IPv6. Those hold the innermost network
	 * addresses, which is the pair ESP is matched on: in this stack the
	 * registration is inside a GTP-U tunnel whose own addresses are of no
	 * interest, and reading them from the same place the matcher does is
	 * also what keeps this from having to know in advance whether the
	 * registration is over IPv4 or IPv6, or which carries which. */
	if (pinfo->src.type == AT_IPv4 && pinfo->dst.type == AT_IPv4)
		proto = "IPv4";
	else if (pinfo->src.type == AT_IPv6 && pinfo->dst.type == AT_IPv6)
		proto = "IPv6";
	else
		return;
	pcscf = address_to_str(pinfo->pool, &pinfo->src);
	ue = address_to_str(pinfo->pool, &pinfo->dst);

	keys = (ims_esp_keys_t *)wmem_map_lookup(ims_esp_keys, call);
	client = (ims_esp_spis_t *)wmem_map_lookup(ims_esp_client, call);
	enc = ims_esp_algo(ims_esp_encr, G_N_ELEMENTS(ims_esp_encr), mech.ealg);
	auth = ims_esp_algo(ims_esp_auth, G_N_ELEMENTS(ims_esp_auth), mech.alg);
	if (auth == NULL)
		auth = IMS_ESP_ANY_ICV;

	/* Everything the four records are still made of, the addresses now being
	 * behind us: a challenge to take the keys from, an encryption algorithm
	 * that can be named at all, and ESP rather than the AH nobody deploys. */
	if (keys == NULL || enc == NULL || g_strcmp0(mech.prot, "ah") == 0)
		return;
	if (strcmp(enc, "NULL") != 0 && keys->ck == NULL)
		return;

	/* The SPIs a party hands out are the ones it will receive on: the
	 * P-CSCF's go on the frames sent to it, the UE's on the frames back. */
	directions[0][0] = ue;    directions[0][1] = pcscf;
	directions[1][0] = pcscf; directions[1][1] = ue;

	records = wmem_array_new(wmem_file_scope(), sizeof(const char *));
	for (direction = 0; direction < 2; direction++) {
		const ims_esp_spis_t *spis = direction == 0 ? &offered : client;
		const char *both[2];
		unsigned i;

		if (spis == NULL)
			continue;
		both[0] = spis->spi_c;
		both[1] = spis->spi_s;
		for (i = 0; i < 2; i++) {
			const char *record;

			if (both[i] == NULL)
				continue;
			record = wmem_strdup_printf(wmem_file_scope(),
				"\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"",
				proto, directions[direction][0], directions[direction][1], both[i],
				enc, ims_esp_encr_key(pinfo->pool, mech.ealg, keys->ck),
				auth, ims_esp_auth_key(pinfo->pool, mech.alg, keys->ik));
			ims_esp_install(record);
			wmem_array_append_one(records, record);
		}
	}

	if (wmem_array_get_count(records) > 0)
		p_add_proto_data(wmem_file_scope(), pinfo, proto_ims_esp, 0, records);
}

static int
dissect_ims_esp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	wmem_array_t *records;
	proto_tree *subtree;
	proto_item *item;
	unsigned i;

	/* Nothing to read the headers out of, and nothing that reads them: with
	 * no tree there are no primed fields either. */
	if (!ims_esp_derive_sa || tree == NULL)
		return 0;

	if (!PINFO_FD_VISITED(pinfo))
		ims_esp_derive(pinfo, tree);

	records = (wmem_array_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ims_esp, 0);
	if (records == NULL)
		return 0;

	item = proto_tree_add_item(tree, proto_ims_esp, tvb, 0, 0, ENC_NA);
	proto_item_set_generated(item);
	subtree = proto_item_add_subtree(item, ett_ims_esp);
	for (i = 0; i < wmem_array_get_count(records); i++) {
		const char *record = *(const char **)wmem_array_index(records, i);

		proto_item_set_generated(
			proto_tree_add_string(subtree, hf_ims_esp_sa, tvb, 0, 0, record));
	}
	return 0;
}

void
proto_register_ims_esp(void)
{
	module_t *ims_esp_module;

	static hf_register_info hf[] = {
		{ &hf_ims_esp_sa,
		  { "Security Association", "ims_esp.sa",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "An ESP SA of this registration, as the ESP SAs table holds it", HFILL }
		},
	};

	static int *ett[] = {
		&ett_ims_esp,
	};

	proto_ims_esp = proto_register_protocol("IMS ESP Security Associations",
						"IMS ESP", "ims_esp");
	proto_register_field_array(proto_ims_esp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	ims_esp_module = prefs_register_protocol(proto_ims_esp, proto_reg_handoff_ims_esp);
	prefs_register_bool_preference(ims_esp_module, "derive_sa",
		"Derive ESP SAs from IMS AKA registrations",
		"Read CK, IK and the agreed SPIs out of the SIP registrations in the "
		"capture and add the resulting security associations to the ESP SAs "
		"table, so that ESP-protected Gm traffic dissects",
		&ims_esp_derive_sa);

	ims_esp_keys = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
					      g_str_hash, g_str_equal);
	ims_esp_client = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
						g_str_hash, g_str_equal);
	ims_esp_installed = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
}

void
proto_reg_handoff_ims_esp(void)
{
	static bool registered;
	GArray *wanted;
	unsigned i;

	if (!registered) {
		ims_esp_handle = create_dissector_handle(dissect_ims_esp, proto_ims_esp);
		register_postdissector(ims_esp_handle);
		registered = true;
	}

	/* Resolved here rather than at registration because SIP registers its
	 * fields in the same round this plugin does, and by handoff they are all
	 * in. A missing one leaves this inert instead of priming -1. */
	hf_sip_call_id = proto_registrar_get_id_byname("sip.Call-ID");
	hf_sip_auth_ck = proto_registrar_get_id_byname("sip.auth.ck");
	hf_sip_auth_ik = proto_registrar_get_id_byname("sip.auth.ik");
	hf_sip_security_server = proto_registrar_get_id_byname("sip.Security-Server");
	hf_sip_security_client = proto_registrar_get_id_byname("sip.Security-Client");

	int wanted_hfids[] = {
		hf_sip_call_id, hf_sip_auth_ck, hf_sip_auth_ik,
		hf_sip_security_server, hf_sip_security_client,
	};

	/* Asking for these is what makes the first pass build a tree at all, so
	 * a preference that turns the plugin off has to take them back rather
	 * than only skip the work in dissect_ims_esp. set_postdissector_wanted_hfids
	 * frees whatever it replaces. */
	for (i = 0; i < G_N_ELEMENTS(wanted_hfids); i++) {
		if (wanted_hfids[i] <= 0) {
			set_postdissector_wanted_hfids(ims_esp_handle, NULL);
			return;
		}
	}
	if (!ims_esp_derive_sa) {
		set_postdissector_wanted_hfids(ims_esp_handle, NULL);
		return;
	}
	wanted = g_array_sized_new(false, false, (unsigned)sizeof(int),
				   G_N_ELEMENTS(wanted_hfids));
	g_array_append_vals(wanted, wanted_hfids, G_N_ELEMENTS(wanted_hfids));
	set_postdissector_wanted_hfids(ims_esp_handle, wanted);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
