--
-- Relate SIP, Diameter and RTP by the subscriber a message is about.
--
--     ims.id == "001010000000001"     one subscriber, Gm/Mw through Cx and Gx
--     ims.impi == "001010000000001"   the same one, named by its IMPI
--     ims.impu == "359000000001"      ... and by any of its IMPUs
--     ims.ref == "Cx"                 every Cx message
--     ims.msg == "Cx/MAR"             one command, request leg only
--     ims.related                     identities this frame does not spell
--
-- Nothing on the wire correlates the two protocols. A Cx Session-Id is minted
-- by the CSCF and never appears in SIP; the SIP Call-ID never reaches the HSS.
-- The one thing both sides carry is the subscriber - spelled differently in
-- every header and AVP that holds it:
--
--     REGISTER   Authorization: username="001010000000001@ims.mnc01.mcc001..."
--     REGISTER   To: <sip:001010000000001@ims.mnc01.mcc001...>
--     Cx UAR     User-Name = 001010000000001@ims.mnc01.mcc001...
--     Cx UAR     Public-Identity = sip:001010000000001@ims.mnc01.mcc001...
--     Rx AAR     Subscription-Id-Data = sip:359000000001@ims.mnc01.mcc001...
--     INVITE     To: <tel:+359000000001>
--
-- so every one of them is normalized down to the bare user part and that
-- becomes the key. `ims.id` is added once per distinct identity in the frame,
-- and a display filter matches if any occurrence matches - which is what makes
-- an INVITE come out under both the caller and the callee.
--
-- A number is keyed by its digits alone, so `tel:+359-000-000-001`, a spaced
-- Subscription-Id-Data and a bare 359000000001 are one identity rather than
-- three (`normalize`), and it is filterable either with the leading + or
-- without it (`add_id`). What the tree displays is always the bare form.
--
-- ---------------------------------------------------------------------------
--
-- Those spellings are not all the same *kind* of name, and collapsing them to
-- one field loses the distinction that matters most in IMS. A subscriber has
-- one private identity, the IMPI, which authenticates and is never routed to,
-- and a set of public identities, the IMPUs, which route and never
-- authenticate. So they are two fields, `ims.impi` and `ims.impu`:
--
--     Authorization username, Cx User-Name, <PrivateID>          -> ims.impi
--     To, From, P-Asserted/Preferred-Identity, Request-URI,
--     reg-event aor, Cx Public-Identity, <Identity>,
--     Ro/Rf User-Name                                            -> ims.impu
--     Subscription-Id-Data          -> either, per Subscription-Id-Type
--
-- User-Name is the one of those whose role is the application's to say and not
-- the AVP's, which `user_name_role` is about: reading the Ro one as an IMPI is
-- what used to put the MSISDN on `ims.impi`.
--
-- A UE with no ISIM derives its IMPI from the IMSI and, having no public
-- identity to register with, a temporary one from the IMPI (23.003 s13.4B), so
-- `001010000000001` is the user part of both and every REGISTER spells it in
-- To as readily as in the Authorization header. That temporary identity is
-- barred - the HSS says so in the User-Data of the SAA, and a key that is also
-- an IMPI is the derived one whether or not that message is in the capture
-- (`keep`) - and a barred identity routes to nobody, so it stays an `ims.id`
-- and the IMPI it was derived from, and never reaches `ims.impu`. What is
-- public about this subscriber is the MSISDN.
--
-- Splitting them is the easy half. Relating them is the point: the MSISDN and
-- the IMSI of one subscriber share no substring, so `ims.impu == "359000000001"`
-- and `ims.impi == "001010000000001"` pick out two disjoint sets of frames that
-- are the same person. The registration binds them, and the binding is on the
-- wire in exactly the messages that assert it:
--
--     REGISTER          Authorization username with To - one subscriber, and
--                       the only SIP method trusted to assert it (`sip_frame`
--                       has the reg event package and why it is not a fourth)
--     any Cx/Rx/Gx/Sh   3GPP defines one Diameter message as being about one
--                       subscriber, so all of its identities go together
--     Cx SAA            <PrivateID> with every <PublicIdentity><Identity> of
--                       the User-Data - the whole implicit registration set,
--                       and the only place the MSISDN IMPU and the IMPI ever
--                       appear in the same message
--
-- Those merge the identities into one class per subscriber; every other message
-- only reads it. The distinction is not pedantry - an INVITE holds two
-- subscribers, one in From and one in To, and merging on mere co-occurrence
-- would collapse a whole call flow into one class within a few frames.
--
-- Reading the class back is what puts an IMPI on a frame that only ever spells
-- the MSISDN - the Cx LIR for `tel:359000000001`, say - and those additions are
-- flagged `ims.related`, so a filter can always get back to what a frame
-- actually said. The class only grows, so a frame dissected before the SAA was
-- seen relates less than the same frame dissected after it; nothing is cached
-- across that, and the second look is the complete one.
--
-- Diameter answers need state of a different kind: a UAA or a CCA carries a
-- Session-Id and nothing else, so the identities are remembered per Session-Id
-- from the request and copied onto the answer, flagged as `ims.linked`. SIP
-- needs no such thing - From and To are in every message including responses.
--
-- Media is the third kind of frame and needs no state of this plugin's own. An
-- RTP packet carries no identity whatsoever - a payload type, a sequence number
-- and an SSRC - and the one thing that ties a stream to a subscriber is the SDP
-- that set it up. Wireshark has already resolved that half: the RTP dissector
-- records which frame's SDP claimed this address and port, as a generated
-- `rtp.setup-frame`, and that frame is a SIP frame this postdissector has read.
-- So a media frame borrows the identities of its setup frame, flagged
-- `ims.linked` like a Diameter answer and for the same reason - the frame
-- itself said none of it - under `ims.ref == "Mb"`, the media transport of
-- 23.002:
--
--     ims.id == "359000000001" && ims.ref == "Mb"   one subscriber's media
--     ims.ref == "Mb"                              every stream in the capture
--
-- Both identities of the setup frame, as a rule, because both are on the wire
-- between: the INVITE that offers the media names the caller in From and the
-- callee in To. Borrowed and never binding, though - `unite` is not called for
-- media, or the first talkspurt of every call would merge its two parties into
-- one subscriber. A stream set up any other way, decoded as RTP by hand or
-- found by the heuristic, has no setup frame and stays bare.
--

set_plugin_info({
    version = '2.1',
    description = 'Relates SIP, Diameter and RTP by the subscriber a message is about',
})

local ims = Proto('ims', 'IMS correlation')

local F = {
    id      = ProtoField.string('ims.id', 'Subscriber identity'),
    impi    = ProtoField.string('ims.impi', 'Private identity (IMPI)'),
    impu    = ProtoField.string('ims.impu', 'Public identity (IMPU)'),
    ref     = ProtoField.string('ims.ref', 'Reference point'),
    msg     = ProtoField.string('ims.msg', 'Message'),
    linked  = ProtoField.bool('ims.linked', 'Identity from session state'),
    related = ProtoField.bool('ims.related', 'Identity from the IMPI/IMPU binding'),
}
ims.fields = { F.id, F.impi, F.impu, F.ref, F.msg, F.linked, F.related }

-- Gm and Mw are the same protocol on the same port; only the endpoints tell
-- them apart, and only this deployment knows which those are. The default is
-- the UENET of the compose stack, so `-o ims.ue_subnet:10.0.0.0/8` (tshark and
-- sharkd) or the preference dialog covers anything else. An endpoint inside a
-- tunnel counts as one - see in_ue_subnet.
ims.prefs.ue_subnet = Pref.string('UE subnet', '10.10.0.0/16',
    'SIP with one endpoint in this prefix is Gm, everything else Mw')

-- Every identity-bearing field of both protocols, under the role it carries.
-- Order within a role is irrelevant: all of them are read and the results
-- deduplicated.
local sip = {
    method = Field.new('sip.Method'),
    status = Field.new('sip.Status-Code'),
    cseq   = Field.new('sip.CSeq.method'),
    impi   = {
        Field.new('sip.auth.username'),   -- the Cx User-Name verbatim
    },
    impu   = {
        Field.new('sip.pai.user'),        -- P-Asserted-Identity
        Field.new('sip.ppi.user'),        -- P-Preferred-Identity
        Field.new('sip.to.user'),
        Field.new('sip.from.user'),
        Field.new('sip.r-uri.user'),
        -- the aor of a reg-event NOTIFY body, which Wireshark dissects out of
        -- application/reginfo+xml into a field of its own
        Field.new('reginfo.registration.aor'),
    },
}

local dia = {
    cmd      = Field.new('diameter.cmd.code'),
    app      = Field.new('diameter.applicationId'),
    request  = Field.new('diameter.flags.request'),
    session  = Field.new('diameter.Session-Id'),
    subtype  = Field.new('diameter.Subscription-Id-Type'),
    subdata  = Field.new('diameter.Subscription-Id-Data'),
    -- not in a role list of its own: which identity it holds is
    -- `user_name_role`, per application
    username = Field.new('diameter.User-Name'),
    impu     = {
        Field.new('diameter.Public-Identity'),
    },
}

-- The Cx User-Data (29.228 Annex C) rides in an AVP as a document, and
-- Wireshark hands it to the generic XML dissector, which knows no schema: every
-- element comes out as `xml.tag` and its text as `xml.cdata`, with nothing
-- linking the two. Which element a value came from is the whole question here -
-- `<ServerName>sip:smsc.epc...` is an iFC application server, not an identity -
-- so the two flat lists are put back together in `by_offset` below.
local xml = { tag = Field.new('xml.tag'), cdata = Field.new('xml.cdata') }

-- The elements of the User-Data that carry an identity, and the one that
-- qualifies it. BARRING is not a role - nothing is filed under it - it is how
-- the walk in `read_user_data` knows whose text it is reading.
local BARRING = 'barring'
local USER_DATA = {
    privateid         = 'impi',
    identity          = 'impu',
    barringindication = BARRING,
}

-- The identities the HSS has barred. Session-wide, like the classes and for
-- the same reason: it is barred on every frame that spells it, and all but one
-- of those frames is not the SAA that said so. Cleared in `reset` with the
-- rest of the state, and declared up here because `read_user_data` fills it.
local barred = {}

-- Bumped whenever anything the widening below reads has moved: a class gaining
-- an identity, two classes merging, an identity learnt to be barred. A frame's
-- widened set is reusable exactly while this stands still, which after the
-- registrations at the head of a capture it does.
local gen = 0

-- RFC 4006 Subscription-Id-Type. The IMSI is not literally an IMPI, but with no
-- ISIM the IMPI is derived from it (23.003 s13.3) and normalizing both leaves
-- the same user part, so it keys the same subscriber; an NAI is already in the
-- user@realm shape of an IMPI. Anything unpaired falls back to a public
-- identity, which is what Rx and Gx carry in an IMS deployment.
local SUBSCRIPTION = {
    [0] = 'impu',  -- END_USER_E164
    [1] = 'impi',  -- END_USER_IMSI
    [2] = 'impu',  -- END_USER_SIP_URI
    [3] = 'impi',  -- END_USER_NAI
    [4] = 'impi',  -- END_USER_PRIVATE
}

-- The setup frame of a media stream: the frame whose SDP claimed the address
-- and port this packet is on. RTCP is read the same way and off the same SDP,
-- so the two are one list, each entry carrying the name its frames go out under.
local media = {
    { name = 'RTP',  setup = Field.new('rtp.setup-frame') },
    { name = 'RTCP', setup = Field.new('rtcp.setup-frame') },
}

local ip = { src = Field.new('ip.src'), dst = Field.new('ip.dst') }

local ROLES = { 'impi', 'impu' }

-- Reference point per Diameter application id. Cx and Dx share 16777216 and
-- are indistinguishable without knowing whether the peer is an SLF, so both
-- come out as Cx.
local REF = {
    [0]        = 'base',   -- CER/DWR/DPR, no application
    [3]        = 'Rf',     -- Diameter base accounting, which in IMS is Rf
    [4]        = 'Ro',
    [16777216] = 'Cx',
    [16777217] = 'Sh',
    [16777236] = 'Rx',
    [16777238] = 'Gx',
    [16777251] = 'S6a',
}

-- Command codes as their two-letter stem; R or A is appended per the request
-- bit, which is how 3GPP names them (300 + request = UAR, 300 = UAA). Cx is
-- 29.229, Sh 29.329, S6a 29.272 - and 301 is Server-Assignment while 303 is
-- Multimedia-Auth, not the other way round, which `_ws.col.info` on a capture
-- will confirm.
local CMD = {
    [257] = 'CE', [258] = 'RA', [265] = 'AA', [271] = 'AC', [272] = 'CC',
    [274] = 'AS', [275] = 'ST', [280] = 'DW', [282] = 'DP', [300] = 'UA',
    [301] = 'SA', [302] = 'LI', [303] = 'MA', [304] = 'RT', [305] = 'PP',
    [306] = 'UD', [307] = 'PU', [308] = 'SN', [309] = 'PN', [316] = 'UL',
    [317] = 'CL', [318] = 'AI', [319] = 'ID', [320] = 'DS', [321] = 'PU',
    [322] = 'RS', [323] = 'NO',
}

-- Which identity a User-Name AVP holds is the application's to define, and
-- they do not agree. 29.229 s6.3.1 makes the Cx one the IMPI, 29.272 the S6a
-- one the IMSI; 32.299 defines nothing for Ro and Rf beyond RFC 6733's "the
-- user name", and what a CTF puts there is the served party as SIP asserted
-- it - Kamailio's ims_charging copies the very string it puts in
-- Subscription-Id (`user_name = subscr.id`, ims_ro.c), which is
-- `sip:359000000001@...`, an IMPU. Reading that as an IMPI is what makes the
-- MSISDN of every charged call a private identity.
local USER_NAME = { Ro = 'impu', Rf = 'impu' }

-- Shape settles what the table has no entry for: an IMPI is an NAI (23.003
-- s13.3), a bare user@realm, and never a URI, so a scheme in front of a
-- User-Name says public whoever sent it - which is also the answer for an
-- application this plugin has never heard of.
local function user_name_role(ref, raw)
    if USER_NAME[ref] then return USER_NAME[ref] end
    return tostring(raw):match('^%a[%w%+%-%.]*:') and 'impu' or 'impi'
end

-- ------------------------------------------------------------- identities ---

-- sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org;transport=udp
-- "001010000000001@ims.mnc01.mcc001.3gppnetwork.org"
-- tel:+359-000-000-001
-- 359 000 000 001
--                                                  -> 001010000000001 / 359000000001
local function normalize(raw)
    if raw == nil then return nil end
    local s = tostring(raw)
    -- Every one of these is a find before it is a cut, because a gsub allocates
    -- a string whether or not it replaced anything and most values arrive with
    -- nothing to strip. This function runs on every identity of every frame.
    if s:find('"', 1, true) then s = s:gsub('"', '') end
    if s:find('^%s') or s:find('%s$') then s = s:match('^%s*(.-)%s*$') end
    if s:byte(1) == 60 then s = s:sub(2) end        -- <
    if s:byte(-1) == 62 then s = s:sub(1, -2) end   -- >
    local scheme = s:match('^%a[%w%+%-%.]*:')       -- sip: sips: tel: im: pres:
    if scheme then s = s:sub(#scheme + 1) end
    local param = s:find('[;%?]')                   -- uri parameters and headers
    if param then s = s:sub(1, param - 1) end
    local at = s:find('@', 1, true)                 -- @domain
    if at then s = s:sub(1, at - 1) end
    -- A number is reduced to its digits. RFC 3966 s3 makes -, ., ( and ) visual
    -- separators that carry no meaning, and a Diameter UTF8String holds whatever
    -- the peer wrote into it - Subscription-Id-Data arrives spaced as readily as
    -- it arrives bare - so one subscriber reaches this function as
    -- +359-000-000-001, as 359 000 000 001 and as 359000000001, and all three
    -- have to leave it as one key or the correlation splits three ways.
    --
    -- Only a value that is nothing but digits and separators is touched. The
    -- same characters are ordinary in the user part of an IMPI or a SIP URI,
    -- where `alice.smith` and `user-1` are names rather than numbers, and
    -- pulling the punctuation out of those would key two subscribers alike.
    if s:match('^%+?[%d%s%-%.%(%)]+$') then
        s = s:gsub('[%s%-%.%(%)]', '')
    end
    if s:byte(1) == 43 then s = s:sub(2) end        -- E.164 international prefix
    if s:find('%u') then s = s:lower() end
    if s == '' then return nil end
    return s
end

local function push(list, seen, value)
    if value and not seen[value] then
        seen[value] = true
        list[#list + 1] = value
    end
end

-- An identity set: the keys of one frame, or of one subscriber, held once per
-- role and once overall. `all` is what `ims.id` is drawn from, and keeping it
-- separate is what lets a key be an IMPI and an IMPU at the same time without
-- being listed twice as a subscriber identity.
local function new_set()
    return { all = {}, seen = {}, impi = {}, impu = {}, roles = { impi = {}, impu = {} } }
end

local function add(set, key, role)
    if key == nil then return false end
    -- a table per role rather than one keyed `role .. ' ' .. key`, which was a
    -- string built and hashed for every identity of every frame
    local of_role = set.roles[role]
    local fresh = not of_role[key]
    if fresh then
        of_role[key] = true
        set[role][#set[role] + 1] = key
    end
    push(set.all, set.seen, key)
    return fresh
end

local function empty(set)
    return #set.impi == 0 and #set.impu == 0
end

local function read(set, role, fields)
    for _, field in ipairs(fields) do
        for _, fi in ipairs { field() } do
            add(set, normalize(fi.value), role)
        end
    end
end

-- what the walk below answers with when there is nothing to walk, shared rather
-- than allocated afresh for every frame that has neither field in it
local NOTHING = {}

-- Two Wireshark fields that belong together - an element with its text, a
-- Subscription-Id-Type with its Data - arrive as two flat lists with nothing
-- linking them. Both were added in wire order out of the same tvb, so sorting
-- the pair by offset puts every value directly after the thing that names it,
-- and one walk down that list carries the name forward. Offsets are only ever
-- compared within one tvb here, which is why the SIP headers and an XML body
-- are never sorted against each other.
--
-- Ties are real and have to be broken all the way down: an element and the one
-- that closes it can be reported at the same offset, and `table.sort` raises
-- "invalid order function" rather than shrugging if the comparison says two
-- items each precede the other. Ranking names before values and falling back to
-- the order they were read in makes it a total order, so there is no such pair.
local function by_offset(names, values)
    -- Neither field is in this frame, which is the usual answer: no Diameter
    -- message carries both a Subscription-Id and a User-Data document, and most
    -- carry neither. Two extractor calls to find that out are cheaper than the
    -- two tables and the sort below.
    if names() == nil and values() == nil then return NOTHING end
    local items = {}
    for _, fi in ipairs { names() } do
        items[#items + 1] = { off = fi.offset, seq = #items, rank = 0, name = tostring(fi.value) }
    end
    for _, fi in ipairs { values() } do
        items[#items + 1] = { off = fi.offset, seq = #items, rank = 1, value = fi.value }
    end
    table.sort(items, function(a, b)
        if a.off ~= b.off then return a.off < b.off end
        if a.rank ~= b.rank then return a.rank < b.rank end
        return a.seq < b.seq
    end)
    return items
end

-- <PrivateID>001010000000001@...</PrivateID> is the IMPI and every
-- <PublicIdentity><Identity> is one IMPU of the same subscriber. Any other
-- element of the User-Data, and any other XML in the frame, is skipped.
--
-- Except <BarringIndication>, which is not an identity but decides what kind
-- one is. It qualifies the <Identity> of its own <PublicIdentity> element and
-- the schema puts it first (tPublicIdentity of the CxDataType, 29.228 Annex
-- C), so carrying the flag forward from the element that opened the pair to
-- the identity that follows it is enough. A barred identity is remembered as
-- such for the whole session, because it is barred wherever it turns up and
-- most of the frames that spell it are not this one.
local function read_user_data(set)
    local current, barring
    for _, item in ipairs(by_offset(xml.tag, xml.cdata)) do
        if item.name then
            -- open and close tags arrive alike, and a close ends the element it
            -- names rather than starting one, so it clears the role instead
            local element = item.name:lower():gsub('[^%a]', '')
            if item.name:match('^%s*</') then
                current = nil
            else
                current = USER_DATA[element]
                -- the identity this one is about has not been read yet
                if element == 'publicidentity' then barring = false end
            end
        elseif current == BARRING then
            -- tBool is an xs:boolean, so both spellings of true are one
            local flag = tostring(item.value):lower():gsub('%s', '')
            barring = flag == '1' or flag == 'true'
        elseif current then
            local key = normalize(item.value)
            if key and barring and current == 'impu' and not barred[key] then
                barred[key] = true
                gen = gen + 1
            end
            add(set, key, current)
        end
    end
end

-- Subscription-Id is a grouped AVP, so the type and the data are separate
-- fields and only their order says which belongs to which.
local function read_subscription(set)
    local current
    for _, item in ipairs(by_offset(dia.subtype, dia.subdata)) do
        if item.name then
            current = SUBSCRIPTION[tonumber(item.name)]
        else
            add(set, normalize(item.value), current or 'impu')
            current = nil
        end
    end
end

-- ------------------------------------------------------------------ state ---

-- What a frame said when it turned out to say nothing, which is a different
-- thing from not having been looked at - see the dissector.
local NONE = {}

-- Per-frame results, so a filter, a click in webshark and a second pass all
-- agree on what a frame said (see the dissector for what is and is not cached).
-- Session-Id -> identity set is the request state the answers are stitched
-- from, and class_of is the IMPI/IMPU binding every frame is read through.
-- `barred`, the third of them, is declared with the User-Data reader that
-- fills it.
local cache, by_session, class_of
local ue_net, ue_bits

local function parse_subnet(pref)
    local addr, bits = tostring(pref):match('^%s*([%d%.]+)%s*/%s*(%d+)%s*$')
    if not addr then return nil, nil end
    local a, b, c, d = addr:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
    if not a then return nil, nil end
    return ((tonumber(a) * 256 + tonumber(b)) * 256 + tonumber(c)) * 256 + tonumber(d),
        tonumber(bits)
end

-- the size of the prefix's host part, which is the same for every address
-- compared against it and so is worked out with the prefix rather than per frame
local ue_block

local function reset()
    cache, by_session, class_of, barred = {}, {}, {}, {}
    ue_net, ue_bits = parse_subnet(ims.prefs.ue_subnet)
    ue_block = ue_bits and 2 ^ (32 - ue_bits) or nil
    gen = gen + 1
end

-- Wireshark runs the init routine once per capture file, which is what stops
-- frame 7 of one file being answered with what frame 7 of the last one held.
-- Called here too, so no dissection can land on empty tables.
reset()
ims.init = reset
-- the cache holds Gm/Mw decisions taken under the old prefix, so it goes with
-- it; everything is recomputed on the redissection this callback triggers
ims.prefs_changed = reset

-- Every address the frame carries and not just the first, because a Gm leg is
-- often tunnelled: SIP between the UE and the P-CSCF crosses N3/S1-U inside
-- GTP-U, and there the UE's own address is in the inner header while the outer
-- one is the tunnel's, between two nodes no subnet of subscribers holds. A field
-- called on its own answers with the first of its occurrences, which is the
-- outer - so the whole of the frame is read instead, and an end in the subnet at
-- any layer of it is the UE's end.
local function in_ue_subnet(field)
    if not ue_net then return false end
    for _, fi in ipairs({ field() }) do
        local a, b, c, d = tostring(fi.value):match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
        if a then
            local addr = ((tonumber(a) * 256 + tonumber(b)) * 256 + tonumber(c)) * 256 +
                tonumber(d)
            -- integer division by the host-part size compares the prefixes without
            -- needing bitwise operators, which Lua 5.1 does not have
            if math.floor(addr / ue_block) == math.floor(ue_net / ue_block) then
                return true
            end
        end
    end
    return false
end

-- ------------------------------------------------------------ subscribers ---

-- One class per subscriber, holding every spelling of them seen so far under
-- the role it was seen in, and reachable from any one of those spellings.

-- Merge the identities of a message that is about a single subscriber. Classes
-- already holding any of them are absorbed into one, which is how the IMPI of
-- a REGISTER and the MSISDN IMPU of the SAA that follows it end up together.
local function unite(observed)
    local target, moved
    for _, role in ipairs(ROLES) do
        for _, key in ipairs(observed[role]) do
            local cls = class_of[key]
            if cls and cls ~= target then
                if not target then
                    target = cls
                else
                    moved = true
                    for _, r in ipairs(ROLES) do
                        for _, k in ipairs(cls[r]) do
                            add(target, k, r)
                            class_of[k] = target
                        end
                    end
                end
            end
        end
    end
    if not target then target, moved = new_set(), true end
    for _, role in ipairs(ROLES) do
        for _, key in ipairs(observed[role]) do
            if add(target, key, role) then moved = true end
            if class_of[key] ~= target then
                class_of[key] = target
                moved = true
            end
        end
    end
    -- The hundredth REGISTER of a subscriber already bound binds nothing, and
    -- every frame's widened set stays as good as it was. Saying so is what keeps
    -- `gen` still over the long tail of a capture.
    if moved then gen = gen + 1 end
end

-- A key refused the public role is still a key: it is what the REGISTER
-- spells, how the frame reaches its class, and what `ims.id` has to match.
-- What is dropped is only the claim that somebody can be reached at it.
--
-- Two things make that claim false. The HSS can say so outright, in the
-- <BarringIndication> of the User-Data it hands out - a barred identity routes
-- to nobody, that being what barred means. And a key that is also an IMPI says
-- it by being one: identities are keyed by their bare user part, so a public
-- identity that keys the same as a private one is the temporary public
-- identity derived from it (23.003 s13.4B), which exists because a UE with no
-- ISIM has nothing else to put in the To of its first REGISTER, and which that
-- same clause bars. The second rule is what holds in a capture that begins
-- after the registration the first one would have been learned from.
--
-- Filtering here rather than in the tree is also what keeps `ims.related`
-- honest: an addition nobody can see is not one the flag should claim.
local function keep(out, private, key, role)
    if role == 'impu' and (barred[key] or private[key]) then
        push(out.all, out.seen, key)
        return false
    end
    return add(out, key, role)
end

-- What the frame spells, plus everything else those subscribers are known by.
-- Returns the widened set and whether anything was in fact added, which is what
-- `ims.related` reports.
local function relate(observed)
    local out, related = new_set(), false
    local classes, seen = {}, {}
    for _, role in ipairs(ROLES) do
        for _, key in ipairs(observed[role]) do
            local cls = class_of[key]
            if cls and not seen[cls] then
                seen[cls] = true
                classes[#classes + 1] = cls
            end
        end
    end

    -- every private identity in play, gathered before anything is added: a
    -- frame that spells only the temporary identity - an Rx AAR for it, say -
    -- learns that it is a private one from the class rather than from itself
    local private = {}
    for _, key in ipairs(observed.impi) do private[key] = true end
    for _, cls in ipairs(classes) do
        for _, key in ipairs(cls.impi) do private[key] = true end
    end

    for _, role in ipairs(ROLES) do
        for _, key in ipairs(observed[role]) do
            keep(out, private, key, role)
        end
    end
    for _, cls in ipairs(classes) do
        for _, role in ipairs(ROLES) do
            for _, key in ipairs(cls[role]) do
                if keep(out, private, key, role) then related = true end
            end
        end
    end
    return out, related
end

-- --------------------------------------------------------------- per frame ---

local function truthy(v) return v == true or v == 1 end

local function diameter_frame()
    -- asked first and singly: `{ dia.cmd() }` is a table built for every frame
    -- in the capture, and all but a few of them have no Diameter in them at all
    if dia.cmd() == nil then return nil end
    local codes = { dia.cmd() }

    local apps, requests = { dia.app() }, { dia.request() }
    local entry = { observed = new_set(), msgs = {} }

    for i, code in ipairs(codes) do
        local app = apps[i] or apps[1]
        local request = truthy(requests[i] and requests[i].value)
        local ref = REF[app and app.value] or ('app' .. tostring(app and app.value))
        local stem = CMD[code.value]
        entry.ref = entry.ref or ref
        entry.msgs[#entry.msgs + 1] = stem
            and string.format('%s/%s%s', ref, stem, request and 'R' or 'A')
            or string.format('%s/%d%s', ref, code.value, request and 'R' or 'A')
    end

    for _, fi in ipairs { dia.username() } do
        add(entry.observed, normalize(fi.value), user_name_role(entry.ref, fi.value))
    end
    read(entry.observed, 'impu', dia.impu)
    read_subscription(entry.observed)
    read_user_data(entry.observed)

    local sessions = {}
    for _, fi in ipairs { dia.session() } do
        sessions[#sessions + 1] = tostring(fi.value)
    end

    if not empty(entry.observed) then
        if #sessions == 1 then
            by_session[sessions[1]] = entry.observed
        end
        -- One message per frame is the norm and then everything in it is one
        -- subscriber's, which is what makes a Cx command a binding. A TCP
        -- segment carrying several messages says nothing of the sort - two
        -- subscribers' commands travel in one segment as readily as one's - so
        -- the identities are still read but nothing is bound or remembered.
        if #codes == 1 then unite(entry.observed) end
    else
        for _, session in ipairs(sessions) do
            local remembered = by_session[session]
            if remembered then
                for _, role in ipairs(ROLES) do
                    for _, key in ipairs(remembered[role]) do
                        add(entry.observed, key, role)
                        entry.linked = true
                    end
                end
            end
        end
    end

    return entry
end

local function sip_frame()
    if sip.method() == nil and sip.status() == nil then return nil end
    local methods, statuses = { sip.method() }, { sip.status() }

    local entry = { observed = new_set(), msgs = {} }
    entry.ref = (in_ue_subnet(ip.src) or in_ue_subnet(ip.dst)) and 'Gm' or 'Mw'

    read(entry.observed, 'impi', sip.impi)
    read(entry.observed, 'impu', sip.impu)

    for _, fi in ipairs(methods) do
        entry.msgs[#entry.msgs + 1] = tostring(fi.value)
    end
    -- a response is named after the transaction it answers, so the filter for
    -- "the 401 to a REGISTER" does not also catch the 401 to an INVITE
    local cseq = { sip.cseq() }
    for i, fi in ipairs(statuses) do
        local method = cseq[i] or cseq[1]
        entry.msgs[#entry.msgs + 1] = method
            and string.format('%s %d', tostring(method.value), fi.value)
            or tostring(fi.value)
    end

    -- Registration is the one SIP transaction whose every identity is one
    -- subscriber's: To equals From, and the Authorization username beside them
    -- is that subscriber's IMPI. A dialog-forming request is the opposite - two
    -- subscribers in one message - so the method is what decides, on the CSeq
    -- rather than the request line, which covers the responses too.
    --
    -- `Event: reg` looks like it belongs here as well, since the aor of a
    -- reg-event NOTIFY is an IMPU of the user it is about. It does not: the test
    -- UA of this stack leaves Event and Accept on its INVITE from the SUBSCRIBE
    -- it built that message out of, and trusting the header merges the caller
    -- with the callee on the first call in the capture. A binding rule is only
    -- worth having if a malformed message cannot invoke it, and the aor of a
    -- genuine NOTIFY is bound by the SAA long before the NOTIFY is sent.
    for _, fi in ipairs(cseq) do
        if tostring(fi.value):upper() == 'REGISTER' then
            unite(entry.observed)
            break
        end
    end

    return entry
end

-- Whoever the SDP that set this stream up was between. Nothing is read off the
-- media itself, so a frame whose setup frame this session has not dissected yet
-- comes out as what it is without who it is between, and says so in `partial`.
local function media_frame()
    for _, m in ipairs(media) do
        local fi = m.setup()
        if fi then
            -- Mb of 23.002. Its access and core legs are not named apart the
            -- way Gm and Mw are, so both come out as Mb.
            local entry = { observed = new_set(), msgs = { m.name }, ref = 'Mb' }
            -- The setup frame can be in the cache as NONE: a stream may be set
            -- up by something that is neither SIP nor Diameter - a SAP
            -- announcement, say - and such a frame says nothing this plugin
            -- reads. It is as unknown to us as one never dissected, and gets the
            -- same partial answer.
            local setup = cache[fi.value]
            if setup and setup ~= NONE then
                for _, role in ipairs(ROLES) do
                    for _, key in ipairs(setup.observed[role]) do
                        add(entry.observed, key, role)
                        entry.linked = true
                    end
                end
            else
                entry.partial = true
            end
            return entry
        end
    end
    return nil
end

-- Every identity is keyed bare, so `ims.impu == "359000000001"` is the filter
-- that works and the `+359000000001` copied straight out of a To header is the
-- one that comes back empty. A number therefore goes in twice, the second item
-- hidden: a hidden item is left out of the tree but still offered to the filter
-- engine, so either form of the number finds the frame and only one of them is
-- on display.
local function add_id(st, field, id)
    st:add(field, id)
    if id:match('^%d+$') then
        st:add(field, '+' .. id):set_hidden(true)
    end
end

-- Most passes over a capture are not reading any of this: the load, the columns
-- of a packet list, a filter about TCP. A display filter primes the fields it
-- names, so `referenced` is true on exactly the passes whose answer depends on
-- this plugin, and a tree built to be shown wants everything and says so with
-- `visible`. tshark's single pass primes the same way, so -Y ims.id is answered
-- there as it is here.
--
-- Which of the fields is worth keeping too: a filter on `ims.msg` or `ims.ref`
-- is answered out of the frame itself and never needs the identities, which are
-- the expensive half of the work below.
local W = {}
local handle   -- ...and `ims` alone, which names the protocol rather than a field

local function wanted(tree)
    local vis = tree.visible
    W.vis     = vis
    W.id      = vis or tree:referenced(F.id)
    W.impi    = vis or tree:referenced(F.impi)
    W.impu    = vis or tree:referenced(F.impu)
    W.ref     = vis or tree:referenced(F.ref)
    W.msg     = vis or tree:referenced(F.msg)
    W.linked  = vis or tree:referenced(F.linked)
    W.related = vis or tree:referenced(F.related)
    if W.id or W.impi or W.impu or W.ref or W.msg or W.linked or W.related then
        return true
    end
    -- `ims` on its own: whether the frame is one of ours is the whole question,
    -- and the protocol item below is the whole answer
    if handle == nil then handle = Dissector.get('ims') or false end
    return handle and tree:referenced(handle) or false
end

function ims.dissector(tvb, pinfo, tree)
    if not wanted(tree) then return end

    -- Two things are cached per frame, and the gate above is what makes the
    -- first of them safe.
    --
    -- What the frame itself said, hit or miss. A miss used to be re-read every
    -- time: sharkd dissects the whole file when it opens it, and on that pass
    -- none of the fields read below are primed - every extractor returns nil -
    -- so a "nothing here" cached from it would stick for the rest of the session
    -- and every filter would come back empty. That pass is now turned away at
    -- the door, so reaching this line means the fields are primed and an empty
    -- read is the frame's own answer rather than an artefact of the pass.
    --
    -- And the widening, which is not the frame's own answer: it is read through
    -- classes that keep growing, and the SAA that ties an IMPI to an MSISDN
    -- comes hundreds of frames after the REGISTER it belongs to. `gen` is when
    -- that last moved, so the set is reused only while everything it was built
    -- from has stood still - which, once a capture's registrations are behind
    -- it, is the whole of the rest of the file.
    --
    -- A media frame is the one entry that can be incomplete rather than absent,
    -- because it is assembled out of another frame's: on a lone click the setup
    -- frame may not have been dissected in this session at all, and caching the
    -- stream without its subscribers would be the permanent miss the first
    -- paragraph is about. A filter pass dissects in frame order, so the SDP is
    -- read before the media it set up and one pass is enough.
    local entry = cache[pinfo.number]
    if entry == nil then
        entry = diameter_frame() or sip_frame() or media_frame()
        if not entry then
            cache[pinfo.number] = NONE
            return
        end
        if not entry.partial then cache[pinfo.number] = entry end
    elseif entry == NONE then
        return
    end

    local ids, related
    if W.id or W.impi or W.impu or W.related then
        ids, related = entry.ids, entry.related
        if ids == nil or entry.gen ~= gen then
            ids, related = relate(entry.observed)
            entry.ids, entry.related, entry.gen = ids, related, gen
        end
    end

    local st = tree:add(ims, tvb(0, 0))
    if W.vis then
        st:set_text(string.format('IMS: %s%s', table.concat(entry.msgs, ' '),
            ids.all[1] and (' ' .. table.concat(ids.all, ' ')) or ''))
        st:set_generated()
    end

    if W.ref and entry.ref then st:add(F.ref, entry.ref) end
    if W.msg then
        for _, msg in ipairs(entry.msgs) do st:add(F.msg, msg) end
    end
    if W.impi then
        for _, id in ipairs(ids.impi) do add_id(st, F.impi, id) end
    end
    if W.impu then
        for _, id in ipairs(ids.impu) do add_id(st, F.impu, id) end
    end
    if W.id then
        for _, id in ipairs(ids.all) do add_id(st, F.id, id) end
    end
    if W.linked and entry.linked then st:add(F.linked, true) end
    if W.related and related then st:add(F.related, true) end
end

register_postdissector(ims)
