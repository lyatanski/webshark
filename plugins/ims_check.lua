--
-- Whether an IMS registration procedure actually completed, and correctly.
--
--     ims_check                          every frame with something to answer for
--     ims.problem                        ...and what it is, in words
--     ims.procedure == "registration"    the procedure a finding belongs to
--
-- ims.lua says what a frame is about. This says whether the frames were right
-- together, which takes evidence of a different kind: not what one message says,
-- but what the messages before it said - and, for a whole class of the findings
-- worth having, what never came at all.
--
-- A finding is raised as one of Wireshark's own expert items as well as a field,
-- so it colours its row in the packet list and its node in the dissection tree
-- with no help from the UI, exactly as a bad checksum does.
--
-- ---------------------------------------------------------------------------
--
-- Two phases, because a postdissector cannot honestly say that something is
-- missing.
--
-- webshark dissects a page of the list at a time, and a clicked frame on its
-- own, so the postdissector is called with whatever the reader happened to open.
-- A finding drawn from that view has to stay true of any larger one, which
-- allows exactly one shape of reasoning: this frame says X, a frame already in
-- hand said Y, and X with Y is wrong. "No SAA ever came" is not that shape. It
-- is a claim about the whole file, and the whole file is the one thing a
-- postdissector never has.
--
-- So the checks that need it run in a Listener instead. A Lua Listener is not
-- run by sharkd's `load`, nor by the `frames` call the packet list is drawn
-- from; it is run by a `tap` call, and then it gets every frame in capture
-- order, with the field extractors primed, and `draw` at the end of the file.
-- (tshark and the Wireshark GUI run it on the read, and need no asking.) That
-- pass is where absence is decidable. `draw` files what it concludes by frame
-- number, and the postdissector attaches it the next time each frame is
-- dissected - the pass itself displays nothing.
--
-- The cost is one full dissection of the capture, which is the thing webshark's
-- lazy load exists to avoid. So it is something a reader asks for, and the
-- findings appear on the refresh after it.
--
-- ---------------------------------------------------------------------------
--
-- What is deliberately not checked: anything the deployment decides. Which AS
-- gets a third-party REGISTER, which iFC fire, how long a registration ought to
-- last, whether IPsec is used at all - a rule about any of those is a rule about
-- one network, and a checker that is wrong about the network it is pointed at is
-- worse than none. What is left is what 3GPP asks of every IMS: the messages of
-- the procedure, their order, and the values the specifications fix.
--
-- The same care is why a check is gated on what the capture holds. A capture
-- taken at the P-CSCF has no Cx in it at all; one at the I-CSCF has UAR and
-- never SAR. Neither is a registration that skipped a step. So nothing is ever
-- reported missing unless the capture proves that message would have been
-- visible in it - which is what `seen` is for.
--

set_plugin_info({
    version = '1.0',
    description = 'Checks the IMS registration procedure across Gm/Mw and Cx',
})

local chk = Proto('ims_check', 'IMS procedure check')

-- The finding, as a field to filter on and an expert item to be seen by. Both,
-- because they answer different questions: `ims.problem` is "show me everything
-- wrong in this capture", and the expert item is what marks the row so that
-- nobody has to think to ask. Under `ims.` rather than `ims_check.` so that one
-- prefix completes to the whole of what this image knows about IMS; the two
-- protocols own their own halves of it and neither minds.
local F = {
    problem   = ProtoField.string('ims.problem', 'Problem'),
    procedure = ProtoField.string('ims.procedure', 'Procedure'),
}
-- Severity is the axis worth splitting on - it is what the packet list draws -
-- so the experts are one per severity and the group is PROTOCOL throughout,
-- rather than sorted into RESPONSE_CODE and SEQUENCE for nobody to read.
--
-- Error is the procedure failing: something answered no. Warning is the
-- procedure completing without something the specifications require of it.
-- Note is what the capture cannot show completing - abandoned rather than wrong.
local E = {
    error = ProtoExpert.new('ims.problem.error', 'IMS procedure failed',
                            expert.group.PROTOCOL, expert.severity.ERROR),
    warn  = ProtoExpert.new('ims.problem.warning', 'IMS procedure incomplete',
                            expert.group.PROTOCOL, expert.severity.WARN),
    note  = ProtoExpert.new('ims.problem.note', 'IMS procedure unfinished',
                            expert.group.PROTOCOL, expert.severity.NOTE),
}
chk.fields  = { F.problem, F.procedure }
chk.experts = { E.error, E.warn, E.note }

local REGISTRATION = 'registration'

local sip = {
    method   = Field.new('sip.Method'),
    status   = Field.new('sip.Status-Code'),
    line     = Field.new('sip.Status-Line'),
    cseq     = Field.new('sip.CSeq.method'),
    seq      = Field.new('sip.CSeq.seq'),
    callid   = Field.new('sip.Call-ID'),
    expires  = Field.new('sip.Expires'),
    contact  = Field.new('sip.Contact'),
    response = Field.new('sip.auth.digest.response'),
    nonce    = Field.new('sip.auth.nonce'),
    route    = Field.new('sip.Service-Route'),
    assoc    = Field.new('sip.P-Associated-URI'),
}

-- An AVP is a field of Wireshark's *dictionary*, which is a set of XML files in
-- the data directory rather than anything compiled in, and `Field.new` raises on
-- a field that was never registered - which would abort this script at its first
-- line and take `ims.problem` with it, leaving the plugin loaded by name and dead
-- in fact. Dockerfile.android has the same warning over the data files it ships
-- for ims.lua. So every AVP is asked for through here: a build whose dictionary
-- is short of one loses the checks that read it and keeps the rest.
--
-- It answers the other half of the same question too. A 3GPP AVP is in the
-- dictionary under the vendor's own name - `diameter.3GPP-SIP-Auth-Data-Item` -
-- and the base dictionary has a field for the same AVP without the prefix that
-- nothing ever fills. Which spellings a build has is its business, so all of
-- them are asked for and whichever answers is the one read.
local function either(...)
    local live = {}
    for _, name in ipairs({ ... }) do
        local ok, f = pcall(Field.new, name)
        if ok then live[#live + 1] = f end
    end
    return function()
        for _, f in ipairs(live) do
            local fi = f()
            if fi then return fi end
        end
        return nil
    end
end

local dia = {
    -- the header, which packet-diameter.c registers itself and no dictionary can
    -- take away
    cmd      = Field.new('diameter.cmd.code'),
    app      = Field.new('diameter.applicationId'),
    request  = Field.new('diameter.flags.request'),
    -- ...and the AVPs, which it cannot - see either() above
    session  = either('diameter.Session-Id'),
    result   = either('diameter.Result-Code'),
    exp      = either('diameter.Experimental-Result-Code'),
    sat      = either('diameter.Server-Assignment-Type',
                      'diameter.3GPP-Server-Assignment-Type'),
    authdata = either('diameter.3GPP-SIP-Auth-Data-Item',
                      'diameter.SIP-Auth-Data-Item'),
}

-- The subscriber, as ims.lua worked it out: the IMPI of a Cx message and the
-- IMPU of the REGISTER that provoked it are one class there, and that class is
-- the only thing tying the two halves of this procedure together - a Cx message
-- names the subscriber and never the Call-ID, and the SIP never carries a
-- Session-Id. Under pcall because this plugin is still worth having without the
-- other one: everything keyed on the Call-ID goes on working, and the checks
-- that cross to Cx quietly do not run.
local has_ims, ims_id = pcall(Field.new, 'ims.id')
if not has_ims then ims_id = nil end

-- Cx and Dx share this; either way the commands below are the registration's.
local CX = 16777216
-- 29.229 s6.1: the three commands a registration is made of, by stem - R or A is
-- appended per the request bit, as 3GPP names them.
local CX_CMD = { [300] = 'UA', [301] = 'SA', [303] = 'MA' }

-- 29.229 s6.2. Cx says yes in the Experimental-Result-Code as readily as in the
-- Result-Code, and its successes are its own: a first registration and a
-- subsequent one are different answers to UAR and both mean proceed.
local CX_OK = {
    [2001] = true,  -- DIAMETER_FIRST_REGISTRATION
    [2002] = true,  -- DIAMETER_SUBSEQUENT_REGISTRATION
    [2003] = true,  -- DIAMETER_UNREGISTERED_SERVICE
    [2004] = true,  -- DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED
}

-- 29.229 s6.3.15, the two ends of Server-Assignment-Type. Only these are
-- compared with the REGISTER that provoked them, because only these are about a
-- REGISTER: a timeout de-registration (4, 6) is the HSS's own doing and an
-- assignment for an unregistered user (3) belongs to a terminating call, so a
-- SAR carrying one of those is left alone rather than measured against a
-- registration it was never part of.
local SAT_REGISTER   = { [1] = true, [2] = true }
local SAT_DEREGISTER = { [5] = true, [7] = true, [8] = true }

-- ------------------------------------------------------------------ state ---

-- Per Call-ID, which is what 24.229 s5.1.1.2 makes the registration's own name:
-- one Call-ID for the initial REGISTER, the challenged one, every refresh and
-- the de-registration. Within it a CSeq names one transaction, which is how a
-- response finds the request it answers.
local calls

-- Per Diameter Session-Id, which is the only thing an answer and its request
-- have in common - ims.lua stitches identities across the same seam. Read by the
-- sweep, for the requests nothing ever answered.
local sessions

-- Every REGISTER and every SAR seen, under each identity ims.lua found on it.
-- Lists rather than a latest, because a frame arrives when the reader opens it
-- and not in order: which of them is "the last one before this frame" is a
-- question to ask at the time, not one to answer by overwriting.
local regs_by_id, sars_by_id

-- What the capture contains, by message name. A check for something missing may
-- only run where this proves the message would have been visible - see the note
-- at the top of the file.
local seen

-- What the sweep concluded, by frame number. Written by draw(), read by the
-- dissector on the next look at each frame.
local swept

local function reset()
    calls, sessions, seen, swept = {}, {}, {}, {}
    regs_by_id, sars_by_id = {}, {}
end

-- Once per capture file, which is what keeps frame 9 of this one from being
-- answered with what frame 9 of the last one did. Called here as well, so that
-- no dissection can land on empty tables.
reset()
chk.init = reset

-- --------------------------------------------------------------- reading ---

local function truthy(v) return v == true or v == 1 end

local function text(fi)
    if not fi then return nil end
    local s = tostring(fi.value)
    return (s:gsub('^"', ''):gsub('"$', ''))
end

local function num(fi)
    if not fi then return nil end
    return tonumber(tostring(fi.value))
end

-- The value as Wireshark's own dictionary labels it - "DIAMETER_ERROR_USER_
-- UNKNOWN (5001)" rather than 5001 - so a finding reads the way the tree reads,
-- and a code this plugin has never heard of still says something.
local function shown(fi)
    if not fi then return '?' end
    local d = fi.display
    if d and d ~= '' then return tostring(d) end
    return tostring(fi.value)
end

-- Every identity on the frame, deduplicated. ims.lua adds the digits of a number
-- twice, once with the leading + and once without, and both are kept: they are
-- two keys onto one subscriber, and a key that finds nothing costs nothing.
local function identities()
    if not ims_id then return {} end
    local out, had = {}, {}
    for _, fi in ipairs({ ims_id() }) do
        local v = tostring(fi.value)
        if not had[v] then had[v] = true; out[#out + 1] = v end
    end
    return out
end

local function remember(index, ids, record)
    for _, id in ipairs(ids) do
        local list = index[id]
        if not list then list = {}; index[id] = list end
        local had = false
        for _, r in ipairs(list) do if r.frame == record.frame then had = true end end
        if not had then list[#list + 1] = record end
    end
end

-- The newest record for this subscriber from before `before`. Newest rather than
-- any, because a subscriber registers, refreshes and de-registers over one
-- capture and what a Cx message is about is the one that has just happened; from
-- before, because a frame may only ever be read against frames that precede it.
local function latest(index, ids, before)
    local best
    for _, id in ipairs(ids) do
        for _, r in ipairs(index[id] or {}) do
            if r.frame < before and (not best or r.frame > best.frame) then best = r end
        end
    end
    return best
end

-- What the REGISTER asked for. A UE says it in the Expires header and a registrar
-- answers in an expires parameter on the Contact, so both are read. Nothing is
-- assumed when neither is there: a REGISTER with no Contact and no Expires is a
-- query for the current bindings rather than a registration, and every check
-- below that turns on the expiry declines to run without one.
local function expiry()
    local e = num(sip.expires())
    if e then return e end
    for _, c in ipairs({ sip.contact() }) do
        local v = tostring(c.value):match('expires=(%d+)')
        if v then return tonumber(v) end
    end
    return nil
end

-- ----------------------------------------------------------- observations ---

local function call_of()
    local cid = text(sip.callid())
    if not cid then return nil end
    local call = calls[cid]
    if not call then call = { id = cid, reg = {}, challenge = {} }; calls[cid] = call end
    return call
end

-- The REGISTER of this frame, filed under its transaction. A retransmission is
-- the same transaction and a finding belongs on the first copy of it, which is
-- what the frame-number test below keeps. Not `sip.resend`, which is the SIP
-- dissector's own answer to the same question: it knows a frame is a resend only
-- once it has seen the frame it resends, and a frame opened on its own is
-- nobody's resend - whereas the lowest frame number is the first copy however
-- the two arrive.
local function note_register(pinfo)
    local call, seq = call_of(), num(sip.seq())
    if not (call and seq) then return nil end
    local was = call.reg[seq]
    if was and was.frame <= pinfo.number then return was end

    local nonce = text(sip.nonce())
    local answer = text(sip.response())
    local r = {
        frame   = pinfo.number,
        seq     = seq,
        call    = call,
        expires = expiry(),
        ids     = identities(),
        nonce   = (nonce ~= '' and nonce or nil),
        -- An IMS UE puts an Authorization header on its very first REGISTER -
        -- that is where the IMPI is (33.203 s6.1) - with the response left
        -- empty, so the header's presence says nothing about whether this
        -- REGISTER answers a challenge and the response value says all of it.
        credentials = (answer ~= nil and answer ~= ''),
    }
    call.reg[seq] = r
    remember(regs_by_id, r.ids, r)
    seen.REGISTER = true
    return r
end

-- ------------------------------------------------------------ the checks ---

local function add(out, expert, why)
    out[#out + 1] = { expert = expert, why = why }
end

-- A response to a REGISTER, which is where nearly everything the SIP half can
-- say goes wrong is visible.
local function check_response(pinfo, out)
    local status = num(sip.status())
    if not status or status < 200 then return end   -- 100 Trying and its kin

    local call, seq = call_of(), num(sip.seq())
    local r = (call and seq) and call.reg[seq] or nil
    -- Which final response it was, for the sweep: a REGISTER nothing ever came
    -- back to is one of the findings, and 401 is a response like any other.
    if r then r.final = status end

    if status == 401 or status == 407 then
        -- The challenge - unless the REGISTER it answers had already answered
        -- one, and this is the network saying the answer was wrong. That is the
        -- one failure in the whole procedure that looks exactly like its normal
        -- course, and the digest response is what tells them apart.
        if call then
            local nonce = text(sip.nonce())
            if nonce and nonce ~= '' then call.challenge[nonce] = pinfo.number end
            call.challenged = pinfo.number
        end
        if r and r.credentials then
            add(out, E.error, 'REGISTER with credentials challenged again (frame '
                .. r.frame .. '): authentication failed')
        end
        return
    end

    if status >= 400 then
        add(out, E.error, 'REGISTER rejected: ' .. (text(sip.line()) or tostring(status)))
        return
    end
    if status >= 300 then return end    -- a redirect is the registrar's to give

    -- A 200 OK, and the S-CSCF owes the UE two things in it (24.229 s5.4.1.2.2).
    -- Only for a registration that authenticated, though: a de-registration has
    -- no route to hand out and no identities to associate, and a third-party
    -- REGISTER to an application server is never challenged and never carries
    -- either. When the REGISTER is not in hand the answer is left alone rather
    -- than guessed at.
    if not r or r.expires == nil or r.expires == 0 then return end
    if not (r.credentials or (call and call.challenged)) then return end
    r.ok = pinfo.number
    if not sip.route() then
        add(out, E.warn, '200 OK to REGISTER without Service-Route (24.229 s5.4.1.2.2)')
    end
    if not sip.assoc() then
        add(out, E.warn, '200 OK to REGISTER without P-Associated-URI (24.229 s5.4.1.2.2)')
    end
end

local function check_sip(pinfo, out)
    local cseq = text(sip.cseq())
    if cseq ~= 'REGISTER' then return end
    if sip.method() then note_register(pinfo) else check_response(pinfo, out) end
end

-- A SAR against the REGISTER that provoked it: the one check here that needs
-- both protocols, and the reason ims.lua's identities are read at all.
--
-- Only the flat contradictions are reported - a registering type for a REGISTER
-- that asked to be forgotten, or the other way about. Which REGISTER it is
-- compared against is the newest this pass has seen for the subscriber, and that
-- is the soft spot in the whole file: a reader who opens the SAR having already
-- opened a REGISTER of the opposite kind, and not the one in between, gets a
-- finding drawn from the wrong one. It takes a subscriber registering and
-- de-registering inside one capture and a frame order nothing reads in, and the
-- sweep puts it right; the alternative is not to make the check at all.
local function check_sar(pinfo, out)
    local sat = dia.sat()
    local v = num(sat)
    if not v then return end
    local reg = latest(regs_by_id, identities(), pinfo.number)
    if not reg or reg.expires == nil then return end

    if SAT_REGISTER[v] and reg.expires == 0 then
        add(out, E.warn, 'Cx/SAR ' .. shown(sat) .. ' for a REGISTER asking to expire (frame '
            .. reg.frame .. ')')
    elseif SAT_DEREGISTER[v] and reg.expires ~= 0 then
        add(out, E.warn, 'Cx/SAR ' .. shown(sat) .. ' for a REGISTER asking for '
            .. reg.expires .. ' s (frame ' .. reg.frame .. ')')
    end
end

local function check_diameter(pinfo, out)
    if num(dia.app()) ~= CX then return end
    local stem = CX_CMD[num(dia.cmd()) or -1]
    if not stem then return end
    local flag = dia.request()
    local request = truthy(flag and flag.value)
    local name = 'Cx/' .. stem .. (request and 'R' or 'A')
    seen[name] = true

    -- The Session-Id with the command on it. The Session-Id alone is what pairs
    -- an answer with its request, and in a Cx that maintains no state it is
    -- minted per transaction anyway - but nothing says it has to be, and two
    -- commands sharing one would otherwise be one another's answers.
    local sid = text(dia.session())
    if sid then sid = sid .. '/' .. stem end

    if request then
        if sid then
            local was = sessions[sid]
            -- lowest frame wins, for the same reason a REGISTER's does, and in
            -- place so that an answer already matched to it stays matched
            if not was then
                sessions[sid] = { frame = pinfo.number, name = name }
            elseif was.frame > pinfo.number then
                was.frame = pinfo.number
            end
        end
        if stem == 'SA' then
            remember(sars_by_id, identities(), { frame = pinfo.number })
            check_sar(pinfo, out)
        end
        return
    end

    if sid and sessions[sid] then sessions[sid].answered = pinfo.number end

    -- Cx answers no in either of two AVPs, and a base-protocol failure and an
    -- application one are both failures of the registration.
    local rc, er = dia.result(), dia.exp()
    local rv, ev = num(rc), num(er)
    if rv and rv >= 3000 then
        add(out, E.error, name .. ': ' .. shown(rc))
        return
    end
    if ev and not CX_OK[ev] then
        add(out, E.error, name .. ': ' .. shown(er))
        return
    end

    -- A MAA that said yes and brought nothing to say it with: the S-CSCF has no
    -- vector to challenge on, so the registration stops here whatever the
    -- Result-Code claims (29.229 s6.1.2).
    if stem == 'MA' and not dia.authdata() then
        add(out, E.warn, 'Cx/MAA with no SIP-Auth-Data-Item: nothing to challenge with')
    end
end

-- ----------------------------------------------------------------- sweep ---

-- Everything above reads a frame against frames it already has. What follows
-- reads the capture against itself, once, at the end of it - see the note at the
-- top for why that is a different pass and what starts it.

local sweep = Listener.new('frame')
function sweep.packet() end

local function file(frame, expert, why)
    local list = swept[frame]
    if not list then list = {}; swept[frame] = list end
    for _, f in ipairs(list) do if f.why == why then return end end
    add(list, expert, why)
end

function sweep.draw()
    -- A Cx request the capture holds no answer to. The request is in it, so the
    -- answer would have been too.
    for _, s in pairs(sessions) do
        if not s.answered then
            file(s.frame, E.warn, s.name .. ' with no answer in the capture')
        end
    end

    for _, call in pairs(calls) do
        local challenges = 0
        for _ in pairs(call.challenge) do challenges = challenges + 1 end
        local credentialled = false

        for _, r in pairs(call.reg) do
            if r.credentials then credentialled = true end

            -- A nonce the capture never offered. Only where it offered some: a
            -- capture that starts after the challenge has none to match against,
            -- and that is a short capture rather than a stale nonce.
            if r.credentials and r.nonce and challenges > 0 and not call.challenge[r.nonce] then
                file(r.frame, E.warn,
                     'REGISTER answering a nonce this capture never offered')
            end

            -- Nothing came back to it at all. A challenge counts as a response
            -- here - 401 is a final one - so what this catches is the REGISTER
            -- that went out into silence.
            if not r.final then
                file(r.frame, E.note, 'REGISTER with no response in the capture')
            end

            -- A registration that authenticated and was told yes, in a capture
            -- that carries SARs - so the S-CSCF's own Cx is in view - and no SAR
            -- for this subscriber between the two. The S-CSCF answered the UE
            -- without ever telling the HSS it was serving them (29.228 s6.1.1).
            if r.ok and r.credentials and seen['Cx/SAR'] then
                local sar = latest(sars_by_id, r.ids, r.ok)
                if not sar or sar.frame < r.frame then
                    file(r.ok, E.warn,
                         'REGISTER accepted with no Cx/SAR for this subscriber')
                end
            end
        end

        -- Challenged, and nothing ever answered the challenge: the UE walked
        -- away, or what it sent next is not in the capture.
        if challenges > 0 and not credentialled then
            file(call.challenged, E.note,
                 'REGISTER challenged, and no REGISTER answering it in the capture')
        end
    end
end

-- ------------------------------------------------------------ per frame ---

function chk.dissector(tvb, pinfo, tree)
    local out = {}
    check_sip(pinfo, out)
    check_diameter(pinfo, out)
    for _, f in ipairs(swept[pinfo.number] or {}) do
        local had = false
        for _, g in ipairs(out) do if g.why == f.why then had = true end end
        if not had then out[#out + 1] = f end
    end
    if #out == 0 then return end

    local st = tree:add(chk, tvb(0, 0))
    st:set_text('IMS check: ' .. out[1].why)
    st:set_generated()
    st:add(F.procedure, REGISTRATION)
    for _, f in ipairs(out) do
        st:add(F.problem, f.why)
        st:add_proto_expert_info(f.expert, f.why)
    end
end

register_postdissector(chk)
