'use strict'

// webshark UI: a paged packet list, the dissection tree, and the bytes. No
// framework and no build step - this file is what the browser runs.
//
// The list holds one screenful of DOM no matter how big the capture is: rows are
// recycled, and pages of PAGE frames are fetched when they scroll into view.
// sharkd caches the filter's match bitmap, so paging through a filtered capture
// costs one dissection per frame drawn, not one per page.
//
// Those rows draw two ways: the packet list, and Wireshark's flow graph - a
// column per address and an arrow per frame. Both read the same pages, so the
// header's List/Flow button is a repaint and nothing else.

// The row height of both views is style.css's --row on #viewer, which the narrow
// layout doubles - so it is measured off the element rather than kept here as a
// second copy of a number that moves on its own.
let ROW = 28       // ...until measure() reads the real one, which it does before any paint
// the capture list's row, which is the packet list's: the same --row, doubled by the
// narrow layout, so it is read back off the element as the packet list's is
let CROW = 28
const PAGE = 200   // frames per /api/frames call
const OVER = 8     // rows drawn above and below the viewport
// fixed widths for the columns Wireshark keeps narrow, the rest to the last one -
// which is Info, and wants everything it can get.
//
// The three time columns are sized to their text rather than guessed at - that
// text being digits, and a countable number of them. A 12px cell of the mono
// stack runs to 7.25px a character at its widest (DejaVu Sans Mono's advance;
// Consolas is a tenth under it), and a row's cell has 12px of padding besides -
// cw() below being the two together. So UTC holds its 27 characters -
// `2026-07-24 15:00:48.910089Z` - in 208px, Time 12 of them in 104 and Delta 9 in 80.
//
// What the two relative formats spend past the six decimals is integer seconds:
// five for Time, a capture that ran 27 hours, and two for Delta, which is the gap
// between *displayed* frames and sub-second in anything unfiltered. Those two are
// a ceiling rather than the width - a capture says how long it ran, and fit()
// narrows the column to the stamps it really holds. Past the ceiling the cell
// ellipsizes, which takes the fractional tail, so the slack is where it costs
// least rather than on every row.
//
// ...and 7.25 is kept below rather than left in the prose: the diagram sizes its
// lanes off the same number, an address over a lifeline being the one label on
// the page that is never allowed to ellipsize - see widest().
const MONO = 7.25
const PAD = 12     // ...and what style.css spends on a cell's padding, both sides
const ADDR = 'Source → Destination'   // the folded pair's own title - see columns()
const WIDE = {
  'No.': 76, Time: 104, Delta: 80, UTC: 208, Source: 150, SrcPort: 70,
  Destination: 150, DstPort: 70, Protocol: 76, Length: 64,
  [ADDR]: 320,
}
// a cell holding n characters of that stack, its own padding included
const cw = n => Math.ceil(n * MONO) + PAD
// What the open capture has narrowed a column to, by title: WIDE is the widest
// each one can be, this is what one of them turns out to want here. Only the time
// columns are ever in it - see fit().
const FIT = {}
const wide = c => FIT[c] || WIDE[c] || 110
const INFO_MIN = 160  // below this the 1fr column would hit 0 and vanish

// The Time column in the three shapes the settings drawer offers. A shape is a
// column format, and sharkd can neither add a column nor reformat one after
// startup - so all three are columns of its own from the very start (see the
// preferences file), two of them hidden, and the pick is only which of them the
// Time slot draws. `col` is the title sharkd gives that column, which is what
// WIDE above and columns() below both key off.
//
// `elapsed` is the two of them that are a length of time rather than a point in
// one, and so the two a capture's own length says the width of - see fit().
const TIMES = [
  { key: 'rel', fmt: '%t', col: 'Time', elapsed: true,
    what: 'Since the capture began', eg: '9.712970' },
  { key: 'delta', fmt: '%Gt', col: 'Delta', elapsed: true,
    what: 'Since the previous displayed frame', eg: '0.000840' },
  { key: 'utc', fmt: '%Yut', col: 'UTC',
    what: 'Absolute, in UTC', eg: '2026-07-24 15:00:48.910089Z' },
]
let TIME = TIMES.find(t => t.key === localStorage.getItem('time')) || TIMES[0]

// The Time column of a capture that ran nine seconds is `9.712970`, eight
// characters; the capture WIDE is sized for spends twelve. `status` says which of
// the two this is, so the column is fitted to the capture rather than left at the
// longest capture it might have been - and the four characters it does not spend
// are 34px, a tenth of a phone's screen. They go to Info in the list and to the
// diagram's lanes, whose room is what the gutter leaves and the gutter is this
// same column (see gutter()).
//
// Downwards only. A capture longer than WIDE allows for keeps that ceiling and
// ellipsizes its fractional tail as it did before, rather than taking a fifth of
// the row from Info to spell out a number every row of the capture shares the
// leading digits of. Delta is held to the same ceiling and bounded by the same
// duration - it is the gap between two displayed frames, and no gap is longer
// than the capture - so what the ceiling has as the common case the fit has as a
// bound.
//
// Called with the capture's `status`, before anything this width reaches is laid
// out: the list's grid (head()) and the diagram's gutter (gutter()).
function fit(st) {
  for (const t of TIMES) delete FIT[t.col]
  if (typeof st.duration !== 'number') return   // a sharkd that does not say
  // integer seconds, the point, and the six decimals after it
  const chars = String(Math.floor(st.duration)).length + 7
  for (const t of TIMES) if (t.elapsed) FIT[t.col] = Math.min(WIDE[t.col], cw(chars))
}

// the flow view's gutter is the list's own No. and Time columns, so a frame's
// number and time sit in the same place whichever view draws it - and it moves
// with the Time column the drawer picked, the list's own having moved
let GUT = 0
const LANE = [160, 400]  // node column: spread to fill the window, between these
// ...and its floor on a phone, where the wide one leaves the diagram a lane and a
// quarter beside the gutter - so an arrow never has both of its ends on screen,
// which is the whole of what a sequence diagram is for. At 100px, and with the
// gutter down to Time alone, the narrowest screen this layout is for holds most
// of three lanes.
//
// A floor and not the width: what the lane is really sized by is the address over
// it, and a lane narrower than that is a label the diagram cannot be read by (see
// widest()). 100px is where a short address leaves it - 10.0.0.1 and the two ×
// slots come to 78 - and anything longer takes the lane it needs.
const LANEP = 100
// The × beside a label and the empty slot mirroring it on the other side, which is
// what keeps the address centred over its own lifeline. style.css draws both off
// --fxw, which gutter() sets from these; the diagram has to know the number
// because the pair comes out of the same lane the address does.
//
// Ten apiece on a phone rather than fourteen, which is 8px less lane behind every
// address on the narrowest screen - and ten is still a button under a thumb.
const FX = 14, FXP = 10
// The cap on the gutter's Time cell on a phone, and so on the whole of that
// gutter - see gutter(). The column's own width is up to 208px there (the UTC
// format), which is half the screen and more than the diagram gets, so an
// absolute stamp is sized to what brief() leaves of it: 12 characters, 104px by
// the rule above WIDE. The two relative formats are already under that and keep
// the width the list gave them, the difference going to the lanes.
const FLOWT = 104
const SIDE = 2     // lanes drawn either side of the window, as OVER is rows

const $ = sel => document.querySelector(sel)

// Every URL webshark asks for is relative to the page it was loaded from, this
// one included: served at / it asks for /api/..., and behind something serving
// it at a path of its own - the operator proxies each webshark at
// /webshark/<namespace>/<name>/ - it asks under that instead, with nothing to
// configure and nothing to rewrite in what comes back.
async function api(path, params, init) {
  const res = await fetch('api/' + path + '?' + new URLSearchParams(params), init)
  const body = await res.json()
  if (body && body.err) throw new Error(body.err)
  return body
}

const S = {
  file: null, filter: '', cols: [], cls: [], lead: 0, total: 0,
  st: null,          // the capture's `status`, kept for columns() to be re-read from
  vis: [],           // row.c indexes the list draws, in order
  ix: {},            // ...and the ones the flow view needs, by name
  view: 'list',
  count: 0,          // frames known to be in the current view
  end: true,         // ...and whether that is all of them
  pages: new Map(),  // page index -> rows, or the Promise fetching them
  selIdx: -1, want: 0,
  nodes: [], node: new Map(),  // flow view: addresses, in the order first seen
  order: [],        // ...or the order they were dragged into, once they have been
  nodeW: LANE[0], width: 0,
  open: new Set(),   // expanded tree nodes by field name, kept across frames
  sources: [], src: 0, mark: null,
  caps: [], find: '',   // the capture list, and the box narrowing it down
  filed: [],            // caps the box leaves, in the order the list draws
  picked: new Set(),    // ...and the ones picked out to be opened as one
}

const list = $('#list'), canvas = $('#canvas'), hex = $('#hex')
const filelist = $('#filelist'), filecanvas = $('#filecanvas')
let slots = []       // recycled row elements
let fileSlots = []   // ...and the capture list's own pool

const flowing = () => S.view === 'flow'

// --row moves with the window (the narrow layout doubles it for the list), and
// every row is placed at a multiple of it - so it is read back after the view or
// the window changes, along with --narrow, which is style.css saying which layout
// that was - and --phone, its second breakpoint, at the width the folded row
// itself stops fitting: what is below that is another set of list columns again
// and another gutter. Both widths stay in that file alone; these two are only
// what it decided.
//
// True if the height moved, which is the caller's cue to put the rows back where
// the new one wants them; a breakpoint crossed without one is the caller's to
// notice - see the ResizeObserver at the end.
let NARROW = false
let PHONE = false
function measure() {
  const css = getComputedStyle($('#viewer'))
  NARROW = css.getPropertyValue('--narrow').trim() === '1'
  PHONE = css.getPropertyValue('--phone').trim() === '1'
  const px = parseFloat(css.getPropertyValue('--row'))
  if (!px || px === ROW) return false
  ROW = px
  return true
}

// ...and on a phone a picked frame leaves either view one row - the diagram's
// header over it, the list's gone by then - holding the row being dissected while
// the tree has the rest of the window. Nothing scrolls to that row: it is put at
// the top and kept there. The narrow band between the two widths keeps its list:
// the panes stack there too, but there is height enough for both of them.
const pinned = () => PHONE && $('#viewer').classList.contains('picked')

// The list lays its columns out in a grid, the flow view as spans over its gutter;
// these carry the two the views share so .num/.ft can size off the same numbers.
//
// A phone shares neither, and keeps only one of them. The list has folded its
// Time column onto the row's second line by then and dropped No. altogether (see
// head()), so there is no shared place left to keep - and what the diagram has
// left over the gutter is 210px of a 390px screen, two lanes, where an arrow
// wants both of its ends and their labels on it. So the same column goes here:
// No. is a position in a list, and this view is not the list. Time stays,
// because when an arrow happened is what the rows are read down, and it stays
// pinned - at the column's own width, but never past FLOWT, brief() making an
// absolute stamp fit that. --numw going to 0 is what slides .ft to the left edge; the
// cell itself is hidden in style.css, padding being the one thing a width of 0
// does not take away.
function gutter() {
  const timew = PHONE ? Math.min(wide(TIME.col), FLOWT) : wide(TIME.col)
  const numw = PHONE ? 0 : WIDE['No.']
  GUT = numw + timew
  $('#viewer').style.setProperty('--numw', numw + 'px')
  $('#viewer').style.setProperty('--timew', timew + 'px')
  // the lane labels' own two slots go out from here as well - the same breakpoint,
  // and layout() sizes a lane around what they leave of it
  $('#viewer').style.setProperty('--fxw', (PHONE ? FXP : FX) + 'px')
}
measure()   // the window may already be narrow, and a paint can come before a resize
gutter()    // ...which is also which of the two gutters this one is

function span(cls, text) {
  const el = document.createElement('span')
  if (cls) el.className = cls
  if (text) el.textContent = text
  return el
}

// the list's folded address column (see columns()): source and destination
// address, each with its port dimmed against it, an arrow between the two
function pair() {
  const el = span()
  el.append(span(), span('port'), span('arrow'), span(), span('port'))
  return el
}

function fillPair(el, row) {
  const [sa, sp, arrow, da, dp] = el.children
  const src = row ? cell(row, 'src') : '', dst = row ? cell(row, 'dst') : ''
  const sport = row ? cell(row, 'sport') : '', dport = row ? cell(row, 'dport') : ''
  sa.textContent = src
  sp.textContent = sport ? ':' + sport : ''
  arrow.textContent = row ? ' → ' : ''
  da.textContent = dst
  dp.textContent = dport ? ':' + dport : ''
  // ...and the addresses the tunnel holds, which the outer pair above replaced
  el.title = row ? inner(row) : ''
}

// ------------------------------------------------------------- packet list ---

function height() {
  // an unfiltered capture knows its length from `status`; a filtered one only
  // finds out when a page comes back short, so leave a page of room to scroll
  // into until then
  return (S.count + (S.end ? 0 : PAGE)) * ROW
}

function rowAt(i) {
  // select() asks for the row before the selected one, so the first row asks for
  // index -1. There is no page -1 to fetch: the negative skip is dropped by the
  // server, page 0 comes back as its contents, and the length of it lands in
  // S.count as -PAGE + length - a negative count draws no rows at all.
  if (i < 0) return null
  const p = Math.floor(i / PAGE), page = S.pages.get(p)
  if (page === undefined) { fetchPage(p); return null }
  if (typeof page.then === 'function') return null
  return page[i - p * PAGE] || null
}

function fetchPage(p) {
  const req = api('frames', { f: S.file, filter: S.filter, skip: p * PAGE, limit: PAGE })
    .then(res => {
      S.pages.set(p, res.rows)
      nodes(res.rows)
      const seen = p * PAGE + res.rows.length
      if (S.filter) {
        S.count = Math.max(S.count, seen)
        if (res.end) { S.count = seen; S.end = true }
      }
      counter(); paint()
    })
    .catch(err => { S.pages.delete(p); note(err.message) })
  S.pages.set(p, req)
  return req
}

// A slot is built for the view that is current when it first appears; switching
// views throws the lot away, so the two shapes never have to convert into each
// other.
function slot(i) {
  while (slots.length <= i) {
    const el = document.createElement('div')
    if (flowing()) {
      el.className = 'frow'
      const label = span('fl')
      label.append(document.createElement('i'), span())
      const line = document.createElement('div')
      line.className = 'fa'
      line.append(label, span('fp a'), span('fp b'))
      el.append(span('num'), span('ft'), line)
    } else {
      el.className = 'row'
      S.cols.forEach((title, c) => {
        const cell = S.vis[c] === 'addr' ? pair() : span()
        cell.className = S.cls[c]
        el.appendChild(cell)
      })
    }
    el.addEventListener('mousedown', () => {
      const i = +el.dataset.i
      if (i === S.selIdx) deselect(); else select(i)
    })
    canvas.appendChild(el)
    slots.push(el)
  }
  return slots[i]
}

let queued = false
function paint() {
  if (queued) return
  queued = true
  requestAnimationFrame(() => { queued = false; draw() })
}

function draw() {
  if (flowing()) layout()
  canvas.style.height = height() + 'px'
  const last = S.count + (S.end ? 0 : PAGE)
  const first = Math.max(0, Math.floor(list.scrollTop / ROW) - OVER)
  const upto = Math.min(last, first + Math.ceil(list.clientHeight / ROW) + OVER * 2)

  let s = 0
  for (let i = first; i < upto; i++, s++) {
    const row = rowAt(i), el = slot(s)
    el.style.top = i * ROW + 'px'
    el.dataset.i = i
    el.hidden = false
    el.classList.toggle('sel', i === S.selIdx)
    el.classList.toggle('gap', !row)
    hue(el, row, i === S.selIdx)
    expert(el, row)
    if (flowing()) arrow(el, row)
    else {
      const cells = el.children
      for (let c = 0; c < S.vis.length; c++) {
        if (S.vis[c] === 'addr') fillPair(cells[c], row)
        else cells[c].textContent = row ? (row.c[S.vis[c]] || '') : (c === S.lead ? '…' : '')
      }
    }
  }
  for (; s < slots.length; s++) slots[s].hidden = true
}

function reveal(i) {
  // the height the canvas is *about* to be drawn at: scrolling into a canvas that
  // has not been drawn yet - opening a link with a frame in it - clamps to 0
  canvas.style.height = height() + 'px'
  // the only row there is, directly under the header band - see style.css
  if (pinned()) { list.scrollTop = i * ROW; return }
  if (i * ROW < list.scrollTop) list.scrollTop = i * ROW
  const bottom = ROW + (i + 1) * ROW    // the sticky header owns the first row
  if (bottom - list.scrollTop > list.clientHeight) list.scrollTop = bottom - list.clientHeight
}

// ...and sideways, which is the diagram's alone: a row there is an arrow between two
// of its lanes, and a capture with more lanes than the window holds has no reason to
// have put that arrow anywhere near it.
//
// The scroll is the least that brings the arrow on screen, exactly as the vertical
// one above is - so an arrow already in view moves nothing, and a conversation
// arrowed through a frame at a time sits still once its two lanes are on screen
// rather than swinging between its ends. An arrow wider than the window has no
// position that shows both, and lands on the left one.
function revealX(row) {
  if (!flowing() || !row) return
  layout()   // the lanes may not have been laid out at this width yet - see above
  const from = S.node.get(cell(row, 'src')), to = S.node.get(cell(row, 'dst'))
  // a frame the address columns left an end of blank has no arrow: arrow() draws it
  // as plain text from the gutter on, which is where the diagram itself starts
  const ends = from === undefined || to === undefined ? [GUT, GUT] : [x(from), x(to)]
  const pad = S.nodeW >> 1   // ...and with either end, the whole of the label over it
  const lo = Math.min(...ends) - pad, hi = Math.max(...ends) + pad
  // the window shows the diagram from the pinned gutter on, not from its own left
  // edge: an arrow tucked behind No. and Time is one that has to be scrolled to
  if (lo - GUT < list.scrollLeft) list.scrollLeft = lo - GUT
  else if (hi - list.scrollLeft > list.clientWidth) {
    list.scrollLeft = Math.min(lo - GUT, hi - list.clientWidth)
  }
}

async function select(i) {
  let row = rowAt(i)
  if (!row) {
    // paging down or clicking into a page still in flight: wait for it rather
    // than making the keypress look ignored
    const pending = S.pages.get(Math.floor(i / PAGE))
    if (pending && typeof pending.then === 'function') { await pending; row = rowAt(i) }
    if (!row) return
  }
  S.selIdx = i
  S.want = row.n
  revealX(row)   // reveal() has put the row on screen; the diagram has an axis more
  sync(); paint()

  const prev = rowAt(i - 1)
  const frame = await api('frame', { f: S.file, num: row.n, prev: prev ? prev.n : 0 })
    .catch(err => { note(err.message); return null })
  if (!frame || S.want !== row.n) return   // a faster click won
  show(frame)
}

function deselect() {
  S.selIdx = -1
  S.want = 0
  $('#viewer').classList.remove('picked')
  $('#tree').textContent = ''
  hex.textContent = ''
  $('#sources').textContent = ''
  $('#field').textContent = ''
  sync(); paint()
}

function move(delta) {
  const to = Math.max(0, Math.min(S.count - 1, (S.selIdx < 0 ? 0 : S.selIdx + delta)))
  reveal(to)
  select(to)
}

// ------------------------------------------------------------------ columns ---

// A row is every column sharkd sent, hidden ones included, so the flow view finds
// the addresses and the ports by column *format* rather than by position - and a
// sharkd configured differently, or not at all, still lines up. Four of the columns
// are this image's own (see the preferences file): the two ports, without which the
// diagram has none to label its arrows with, and the Time column's two alternatives
// - see TIMES - which are hidden ones, sent with every row and reported as
// `visible: false`, so they stay out of the list until the drawer asks for one.
//
// Called again, off the status kept here, whenever the drawer picks another of
// those: which columns a row holds is the capture's, which of them the list draws
// is the setting's.
function columns(st) {
  const info = st.column_info ||
    (st.columns || []).map(title => ({ title, format: '', visible: true }))
  S.st = st
  const shown = info.map((_, i) => i).filter(i => info[i].visible !== false)

  const at = (fmt, title) => {
    const i = info.findIndex(c => c.format === fmt)
    return i >= 0 ? i : info.findIndex(c => c.title === title)
  }
  // the Time column the drawer asked for, or - from a sharkd whose columns are not
  // this image's - the one Wireshark has by default
  const rel = at('%t', 'Time'), picked = at(TIME.fmt, TIME.col)
  S.ix = {
    time: picked >= 0 ? picked : rel,
    src: at('%s', 'Source'), dst: at('%d', 'Destination'),
    sport: at('%uS', 'SrcPort'), dport: at('%uD', 'DstPort'),
    proto: at('%p', 'Protocol'), info: at('%i', 'Info'),
    // the other two the phone layout has a place for; nothing else reads these
    no: at('%m', 'No.'), len: at('%L', 'Length'),
    // ...and the expert pair, hidden like the Time alternatives and read the
    // same way, out of the row rather than off the list - see expert()
    sev: at('%Cus:_ws.expert.severity:0', 'Expert'),
    xinfo: at('%Cus:_ws.expert.message:0', 'Expert info'),
    // ...and the outer end of each address and port, four more hidden ones - which
    // is what the four above turn into wherever a frame is tunnelled, see cell()
    osrc: at('%Cus:ip.src or ipv6.src:1', 'OuterSrc'),
    osport: at('%Cus:udp.srcport or tcp.srcport or sctp.srcport:1', 'OuterSrcPort'),
    odst: at('%Cus:ip.dst or ipv6.dst:1', 'OuterDst'),
    odport: at('%Cus:udp.dstport or tcp.dstport or sctp.dstport:1', 'OuterDstPort'),
  }
  // with no addresses to put in columns there is no diagram to offer
  $('#mode').hidden = S.ix.src < 0 || S.ix.dst < 0
  if ($('#mode').hidden) S.view = 'list'

  // the list folds Source/SrcPort/Destination/DstPort into one column - address:port
  // → address:port - rather than four; 'addr' stands in for the pair in S.vis, and
  // fillPair(), above, reads the four apart again by the same S.ix this leaves in place
  const fold = new Set([S.ix.sport, S.ix.dst, S.ix.dport])
  // ...and the Time slot is one column of three, whichever of them was picked: the
  // alternatives are the drawer's to place, never the list's to draw beside it
  const alts = new Set(TIMES.map(t => at(t.fmt, t.col)).filter(i => i >= 0 && i !== rel))
  const drawn = $('#mode').hidden ? shown
    : shown.filter(i => !fold.has(i)).map(i => i === S.ix.src ? 'addr' : i)
  S.vis = drawn.filter(i => !alts.has(i)).map(i => i === rel ? S.ix.time : i)
  S.cols = S.vis.map(i => i === 'addr' ? ADDR : info[i].title)
  // A class per drawn column, which is how style.css places them: the phone
  // layout deals the row out over its two lines in an order S.cols does not
  // give, and one line of grid tracks cannot say which cell goes where. Found by
  // format, as everything else about a column here is - so a column this app has
  // no name for gets no class, and the phone layout leaves it out rather than
  // dropping it somewhere the tracks did not expect. No. reads as numeric data,
  // so both views set it off from the left-aligned text columns.
  S.cls = S.vis.map(i => i === 'addr' ? 'addr' : CLS[Object.keys(CLS).find(k => S.ix[k] === i)] || '')
}

// the class each column the phone layout can place is drawn with, by the S.ix
// name it is found under
const CLS = { no: 'num', time: 'time', proto: 'proto', len: 'len', info: 'info' }

const raw = (row, name) => (S.ix[name] >= 0 ? row.c[S.ix[name]] : '') || ''

// the hidden column holding the outer end of each of the four the views draw
const OUTER = { src: 'osrc', dst: 'odst', sport: 'osport', dport: 'odport' }

// An address or a port of a row - the outer one where the frame has two.
//
// Wireshark's Source and Destination hold the innermost address a frame has, so a
// GTP-U frame reads as the UE's own address and the SIP port inside it. That is a
// leg the capture never carried: what it did carry is the tunnel, between two
// nodes that are nowhere in the row. Both views are about the hops of the capture
// - the diagram draws a lifeline per address and puts every frame on the one it
// travelled - so the outer end is the one they draw, and the inner pair stays as
// the cell's tooltip (see fillPair) rather than going missing.
//
// The outer column is the first occurrence of each field it lists (see the
// preferences file), which is the outermost. Two of them come back comma-joined
// when the tunnel changed address family - v6 carrying v4, or the reverse - and
// the one that is not what the plain column holds is the outer one either way
// round. An untunnelled frame has the one value, equal to the plain column, and a
// frame with no IP or no ports at all has none: both fall through to the column
// the list has always drawn, a MAC or a resolved name included.
const cell = (row, name) => {
  const v = raw(row, name)
  if (!OUTER[name]) return v
  const out = raw(row, OUTER[name])
  return out ? out.split(',').find(o => o !== v) || v : v
}

// The pair the frame carries inside its tunnel, for the row that draws the outer
// one - and nothing at all for a frame that is not tunnelled.
function inner(row) {
  const src = raw(row, 'src'), dst = raw(row, 'dst')
  if (src === cell(row, 'src') && dst === cell(row, 'dst')) return ''
  const at = p => (p ? ':' + p : '')
  return 'tunnelled: ' + src + at(raw(row, 'sport')) + ' → ' + dst + at(raw(row, 'dport'))
}

// The list's column titles. The flow view's header is the node columns, which
// only layout() knows the geometry of.
function head() {
  const cols = $('#cols')
  cols.textContent = ''
  cols.style.minWidth = ''
  canvas.style.minWidth = ''
  if (flowing()) { unlane(); return }   // the lane slots were among what that emptied
  S.cols.forEach((title, c) => cols.appendChild(span(S.cls[c], title)))
  const last = S.cols.length - 1
  $('#viewer').style.setProperty('--grid',
    S.cols.map((c, i) => i === last ? '1fr' : wide(c) + 'px').join(' '))
  // otherwise a narrow window shrinks the fixed columns' shared box below their
  // own total, and the overflow renders past #cols/canvas with no background to
  // paint it on - the header looks half-transparent and Info can hit 0 width
  const fixed = S.cols.slice(0, last).reduce((sum, c) => sum + wide(c), 0)
  $('#viewer').style.setProperty('--minw', fixed + INFO_MIN + 'px')

  // ...and the same pair again for the narrow layout, where Info has a line of
  // its own and the columns before it have the first (see style.css). Its floor
  // is theirs alone, and its tracks are theirs - one of which has to take the
  // slack, or the line stops short of the row and so does Info under it, which
  // spans the same tracks. The addresses are the column worth the width; a
  // capture with none gets a spacer track instead.
  const lead = S.cols.slice(0, last)
  const give = lead.indexOf(ADDR)
  const tracks = lead.map((c, i) => i === give ? `minmax(${wide(c)}px, 1fr)` : wide(c) + 'px')
  if (give < 0) tracks.push('1fr')
  $('#viewer').style.setProperty('--gridn', tracks.join(' '))
  $('#viewer').style.setProperty('--minwn', fixed + 'px')

  // ...and a third pair, for a phone. The folded row above does not fit one
  // either: its first line is the fixed columns' own total, 648px with the
  // columns this image ships, which is a screen and two thirds - so the row is
  // dealt out over both of its lines rather than folded at Info alone.
  //
  // The addresses take the whole of the first line beside the protocol. They are
  // the column that can least afford an ellipsis: a name cut short is the half of
  // a conversation the row is read for, and unlike Info there is no reading on to
  // recover it. The time and Info have the second.
  //
  // No. is not drawn at all. A screen this size has room for four of these five
  // columns and the frame number is the one worth the least of them - it is a
  // position in a list that is on screen anyway, where every other column is
  // something about the frame - and what dropping it buys is the width it had,
  // which goes to Info. The number is still in the diagram's gutter (see
  // gutter()) and in the first line of the frame's own dissection.
  //
  // Three tracks carry both lines: Protocol, the rest of Time, and what is left.
  // The addresses get everything past the first, and Info everything past Time -
  // so the pair keeps its width whichever shape the Time column is in, and only
  // Info gives way to a wider one. Which cell sits in which is style.css's, by
  // the classes columns() put on them.
  const timew = wide(TIME.col)
  const protow = S.ix.proto >= 0 ? WIDE.Protocol : 0
  $('#viewer').style.setProperty('--gridp',
    `${protow}px ${Math.max(0, timew - protow)}px minmax(0, 1fr)`)
  $('#viewer').style.setProperty('--minwp', Math.max(timew, protow) + 'px')

  // The cell a row whose page is still in flight puts its … in: the leading one
  // of whichever layout is drawing. That is No. in the two above and Protocol
  // here, No. not being drawn at all - and it has to be a column with text of its
  // own, the address pair being filled a span at a time (see fillPair).
  S.lead = PHONE ? (['proto', 'time'].map(k => S.cls.indexOf(k)).find(i => i >= 0) ?? 0) : 0
}

// The views share the pages, the filter and the selection, so switching is a
// repaint - of rows built the other way, hence throwing the slots out.
function view(pick) {
  const top = Math.round(list.scrollTop / ROW)
  S.view = pick
  const button = $('#mode')
  button.classList.toggle('flow', flowing())   // the icon draws whichever view is on
  button.title = flowing()
    ? 'Sequence diagram (click for the packet list)'
    : 'Packet list (click for the sequence diagram)'
  $('#viewer').classList.toggle('flow', flowing())
  measure()                               // the class above rescopes --row when narrow
  for (const el of slots) el.remove()
  slots = []
  unlane()
  head()
  canvas.style.height = height() + 'px'   // as in reveal(): rows of another height
  list.scrollTop = top * ROW              // scroll to the same frame, not the same px
  sync(); paint()
}

$('#mode').onclick = () => view(flowing() ? 'list' : 'flow')

// ----------------------------------------------------------- coloring rules ---

// Wireshark's coloring rules, which sharkd applies as it dissects: a frame comes
// back with the colours of the first rule that matched it, and its row is painted
// with them. The row only carries the pair - what light and dark each make of it
// is style.css's business.
//
// Two rows are left plain. The selected one keeps the selection colour, which has
// to stay the unmistakable thing on the list; a row whose page is still in flight
// has no colours to carry yet.
function hue(el, row, sel) {
  const on = !!(row && row.bg) && !sel
  el.classList.toggle('hue', on)
  if (on) {
    el.style.setProperty('--rbg', '#' + row.bg)
    el.style.setProperty('--rfg', '#' + row.fg)
  }
}

// Wireshark's dissectors judge as they dissect - a checksum that does not add up,
// a retransmission, a Diameter AVP no dictionary has - and file what they find as
// expert items on the frame. Those are in the dissection tree, which is one frame
// at a time; the list is where the frame worth opening has to be found. So a row
// carries the severity of every item on its frame and the summary of each, as two
// hidden columns (see the preferences file), and wears the worst of them.
//
// Weakest first, which is what makes the worst of them a maximum.
const SEV = ['Comment', 'Chat', 'Note', 'Warning', 'Error']
// ...and only from Note up. Chat is every TCP handshake and every SIP request
// line, Comment is a note the capture was saved with, and a mark on a third of
// the rows is a mark on nothing.
const MARKED = SEV.indexOf('Note')

function expert(el, row) {
  // one severity per item, in the order the items are on the frame: an AVP the
  // dictionary does not have raises two, for the code and for the vendor, and the
  // column reads "Warning,Warning"
  let worst = -1
  if (row) for (const s of cell(row, 'sev').split(',')) worst = Math.max(worst, SEV.indexOf(s))
  if (worst < MARKED) {
    delete el.dataset.sev
    el.removeAttribute('title')   // ...and not title = '', which leaves an empty one
    return
  }
  el.dataset.sev = SEV[worst]
  // every summary, not the worst one's: two items on a frame are two things to
  // know about it, and the row has nowhere but this to say either
  el.title = cell(row, 'xinfo')
}

// -------------------------------------------------------- sequence diagram ---

// Wireshark's flow graph: a column per address, a row per frame, an arrow from
// the source's lifeline to the destination's. The columns are the addresses of the
// pages fetched so far - the capture is not read ahead to find the rest, so a
// column appears when a frame using it is first paged in, and the order is the
// order of the frames. Filter first and the diagram is the conversation.
//
// Nothing caps how many. The lanes are drawn the way the rows are - only where the
// window is over them, see layout() - so a capture with hundreds of addresses is a
// diagram hundreds of lanes wide to scroll through, and still a screenful of
// lifelines in the page.
function nodes(rows) {
  let added = false
  for (const row of rows) {
    for (const addr of [cell(row, 'src'), cell(row, 'dst')]) {
      if (!addr || S.node.has(addr)) continue
      S.node.set(addr, S.nodes.length)
      S.nodes.push(addr)
      added = true
    }
  }
  if (added) arrange()   // a new column goes where the arranged ones leave it
}

const lanes = []   // recycled lane slots: a header label and the lifeline under it
let laid = ''      // the geometry, and the run of nodes, those were last laid out for

function unlane() {
  for (const l of lanes) { l.label.remove(); l.life.remove() }
  lanes.length = 0
  laid = ''
}

const x = i => GUT + S.nodeW * i + (S.nodeW >> 1)

// A lane slot is a header label and its lifeline, built once and moved to whichever
// node the window has scrolled over - slot()'s recycling turned sideways. The
// diagram is as wide as the capture has addresses; what is in the page is the
// screenful of lanes the window is on, and layout() puts them back on every scroll.
function laneSlot(s) {
  while (lanes.length <= s) {
    const label = span('fnode')
    const off = document.createElement('button')
    off.className = 'fx'
    off.textContent = '×'
    label.append(span('fname'), off)
    $('#cols').appendChild(label)

    const life = document.createElement('div')
    life.className = 'life'
    canvas.appendChild(life)
    lanes.push({ label, life })
  }
  return lanes[s]
}

// The lane the longest address in the diagram fits in whole: its characters at
// MONO apiece, and the × and its mirror either side of them.
//
// Because a clipped address is not a shorter address - it is the wrong one. The
// hosts of a capture share the network they are on, so the part an address is told
// apart by is the end of it, which is the half an ellipsis takes: a phone at the
// old 100px lane drew a screenful of "192.168.10…", one label the same as the
// next. The lane is sized to the address instead, and the diagram scrolls
// sideways - which it does anyway, having a lane per address of the capture.
//
// LANE[1] is still the ceiling, and no address reaches it: 400px is 51 characters
// where the longest IPv6 address is 39. What can reach it is a resolved name -
// a column of them is not addresses at all - and there style.css's ellipsis is
// still the backstop.
const widest = () =>
  S.nodes.reduce((w, a) => Math.max(w, Math.ceil(a.length * MONO)), 0) +
  2 * (PHONE ? FXP : FX)

function layout() {
  const n = S.nodes.length
  const room = list.clientWidth - GUT - 12
  const min = Math.min(LANE[1], Math.max(PHONE ? LANEP : LANE[0], widest()))
  S.nodeW = Math.max(min, Math.min(LANE[1], n > 0 ? Math.floor(room / n) : min))
  S.width = GUT + S.nodeW * n
  // min, not width: a diagram narrower than the window still wants full-width rows
  // to highlight and a header band that reaches the end of it
  const cols = $('#cols')
  canvas.style.minWidth = S.width + 'px'
  cols.style.minWidth = S.width + 'px'
  // the gutter columns are pinned over the diagram (style.css keeps them there on
  // its own); this is the one thing about them that is not the browser's - once
  // there is diagram behind them they draw an edge to say so
  $('#viewer').classList.toggle('slid', list.scrollLeft > 0)

  // the lanes the window is over, and one either side, so a scroll of a few pixels
  // has a column to move into rather than a gap to draw one in
  const from = Math.max(0, Math.floor((list.scrollLeft - GUT) / S.nodeW) - SIDE)
  const upto = Math.min(n, Math.ceil((list.scrollLeft + list.clientWidth - GUT) / S.nodeW) + SIDE)
  const sig = n + ':' + S.nodeW + ':' + from + ':' + upto
  if (sig === laid) return   // the same lanes, at the same width, in the same place
  laid = sig

  // the gutter's own titles, which head() empties the band of along with the rest
  if (!cols.firstChild) cols.append(span('num', 'No.'), span('ft'))
  cols.children[1].textContent = TIME.col

  let s = 0
  for (let i = from; i < upto; i++, s++) {
    const addr = S.nodes[i]
    const { label, life } = laneSlot(s)
    const held = drag && drag.addr === addr   // the column being dragged right now
    label.className = 'fnode' + (held ? ' grab' : '')
    label.hidden = false
    label.style.left = (x(i) - (S.nodeW >> 1)) + 'px'
    label.style.width = S.nodeW + 'px'
    label.title = addr + '\ndrag to move this column'
    label.dataset.addr = addr
    label.children[0].textContent = addr
    label.children[1].title = 'Hide ' + addr + ' — adds it to the display filter'
    life.className = 'life' + (held ? ' grab' : '')
    life.hidden = false
    life.style.left = x(i) + 'px'
  }
  // the slots the diagram has outgrown for now: kept, so scrolling back is a move
  for (; s < lanes.length; s++) { lanes[s].label.hidden = true; lanes[s].life.hidden = true }
}

// -------------------------------------------------- moving the node columns ---

// The lanes are the diagram's own axis, and the order the frames happened to
// arrive in is rarely the one a conversation reads best in - so a header label
// can be dragged to another lane, and the arrows follow it as it goes. The
// dragged column is held as an address rather than as an element: layout()
// rebuilds the header on every move, so the label under the pointer is a new one
// each time.
let drag = null
let edging = 0               // the frame callback scrolling a drag along, if one is
// the band of the list a held pointer scrolls in, and the pixels per frame it
// scrolls by. On the left the band is the pinned gutter's whole width instead: a
// lane behind No. and Time cannot be seen, so a pointer held over them is asking
// for the lanes further back rather than for the one it happens to be over.
const EDGE = 40, STEP = 14

// #cols scrolls sideways with the rows under it, and every position the diagram
// carries is in the canvas's own coordinates
const canvasX = cx => cx - list.getBoundingClientRect().left + list.scrollLeft
const lane = cx => Math.max(0, Math.min(S.nodes.length - 1,
  Math.floor((canvasX(cx) - GUT) / S.nodeW)))

const renumber = () => { S.node.clear(); S.nodes.forEach((a, i) => S.node.set(a, i)) }

// A column moved to another lane. What is remembered is the addresses in the
// order they now sit in, not the lane each ended up in: hiding a column is a
// filter, a filter throws the pages and with them the node columns away
// (rewind), and the addresses that come back have to land where they were put.
function place(addr, to) {
  const at = S.node.get(addr)
  if (at === undefined || at === to) return
  S.nodes.splice(to, 0, S.nodes.splice(at, 1)[0])
  renumber()
  S.order = S.nodes.slice()
  laid = ''   // the same lanes at the same width, in another order
  paint()
}

// ...and that order re-applied to a node list which has just been built again.
// The sort is stable, so an address nobody has moved keeps its place among the
// ones it was first seen with, and one this order has never heard of - a column
// that only appears now the filter has changed - goes on the end.
function arrange() {
  if (!S.order.length) return
  // a rank apiece rather than an indexOf per comparison: both lists are as long as
  // the capture has addresses, and this runs on every page that brings a new one
  const rank = new Map(S.order.map((a, i) => [a, i]))
  const at = a => rank.has(a) ? rank.get(a) : S.order.length
  S.nodes.sort((a, b) => at(a) - at(b))
  renumber()
  laid = ''
}

$('#cols').addEventListener('pointerdown', e => {
  if (!flowing() || e.button !== 0) return
  const label = e.target.closest('.fnode')
  if (!label || e.target.closest('.fx')) return
  e.preventDefault()   // ...and with it the text selection dragging would make
  drag = { addr: label.dataset.addr, at: e.clientX, from: e.clientX, on: false, edge: 0 }
  addEventListener('pointermove', dragging)
  addEventListener('pointerup', dropped)
  addEventListener('pointercancel', dropped)
})

function dragging(e) {
  if (!drag) return
  drag.at = e.clientX
  // a few pixels of slop, so a click that wobbles is not a reorder
  if (!drag.on && Math.abs(e.clientX - drag.from) < 4) return
  if (!drag.on) {
    drag.on = true
    document.body.classList.add('dragging')
    laid = ''   // the label takes the colours it is dragged in
  }
  place(drag.addr, lane(e.clientX))
  // a lane off the side of the window: the list scrolls itself while the pointer
  // is held near an edge, a pointer held still having no more events to move on
  const box = list.getBoundingClientRect()
  drag.edge = e.clientX > box.right - EDGE ? 1 : e.clientX < box.left + GUT ? -1 : 0
  if (drag.edge && !edging) edging = requestAnimationFrame(scrolling)
  paint()
}

function scrolling() {
  edging = 0
  if (!drag || !drag.edge) return
  const was = list.scrollLeft
  list.scrollLeft += drag.edge * STEP
  if (list.scrollLeft !== was) place(drag.addr, lane(drag.at))
  edging = requestAnimationFrame(scrolling)
}

function dropped() {
  removeEventListener('pointermove', dragging)
  removeEventListener('pointerup', dropped)
  removeEventListener('pointercancel', dropped)
  drag = null
  document.body.classList.remove('dragging')
  if (edging) { cancelAnimationFrame(edging); edging = 0 }
  laid = ''   // ...and puts them back down again
  paint()
}

$('#cols').addEventListener('click', e => {
  const off = e.target.closest('.fx')
  if (off && flowing()) hide(off.parentNode.dataset.addr)
})

// Taking a column out is a filter rather than a hidden column: the frames it drew
// leave both views, the filter box is what says the address is gone - and editing
// it is what brings the column back.
//
// The clause is a negated ==, never a !=: a frame carries an address field at
// each end, and "either of them is not this one" is true of very nearly
// everything.
async function hide(addr) {
  note('Removing ' + addr + '…')
  const term = await addrTerm(addr).catch(() => '')
  if (!term) { note('no field of the capture holds ' + addr + ', so there is no filter for it'); return }
  filter(S.filter ? '(' + S.filter + ') and !(' + term + ')' : '!(' + term + ')')
}

// The clause matching the frames a node column drew - which has to name the field
// the address came out of, and the spelling of an address does not say what that
// is. The columns hold whatever the frame had, and which field holds it is the
// encapsulation's business as much as the address's: a MAC on an Ethernet capture
// is eth.src, the same MAC on a Linux cooked one (which is what `-i any` and
// ptcpdump write) is sll.src.eth, and that has no resolved-name field at all - so
// a filter written against the name Wireshark shows in the column matches nothing
// and the lane silently stays where it was.
//
// So the capture is asked instead. One frame the lane drew is dissected, and every
// node sharkd sends back carries the filter Wireshark itself would apply for that
// field: the resolved name is in the label, the bytes are in the filter.
async function addrTerm(addr) {
  const row = using(addr)
  const frame = row && await api('frame', { f: S.file, num: row.n }).catch(() => null)
  const hit = frame && holder(frame.tree || [], addr)
  const term = hit ? await ends(hit) : guess(addr)
  return term && MAC.test(hit ? hit.value : addr) ? linkOnly(term) : term
}

// A MAC reaches the address column only on a frame with no network layer to name
// an address of its own - an ARP, an STP, an LLDP. The host's IP traffic goes out
// over that same MAC, but the column shows it as the IP, which is a lane of its
// own; so the MAC's clause has to say "at the link layer and nothing above it", or
// hiding the ARP column takes the two IP columns down with it.
//
// Above it is ip and ipv6: the layers that overwrite the address column in any
// capture this side of IPX. Both are always compiled in, so unlike ends() there is
// nothing here to ask the capture about. The clause is parenthesised because it may
// be a two-ended `or` and `and` binds tighter.
const linkOnly = term => '(' + term + ') and not ip and not ipv6'

// a frame the lane drew, out of the pages that are already here - the addresses
// are those pages' own, so there is one
function using(addr) {
  for (const page of S.pages.values()) {
    if (!Array.isArray(page)) continue
    for (const row of page) {
      if (cell(row, 'src') === addr || cell(row, 'dst') === addr) return row
    }
  }
  return null
}

// The first field of the frame's dissection that holds the address. The walk is
// outermost first, so a MAC that is both the link layer's and an ARP payload's
// comes back as the link layer's - the broader of the two. A node qualifies when
// its value is an address at all (a packet type or an offset is not) and either
// that value or the label over it is the address the column showed.
function holder(nodes, addr) {
  for (const n of nodes) {
    const at = (n.f || '').indexOf(' == ')
    if (at > 0) {
      const name = n.f.slice(0, at), value = n.f.slice(at + 4)
      if (looksAddr(value) && (value === addr || shows(n.l, addr))) return { name, value }
    }
    const deeper = n.n && holder(n.n, addr)
    if (deeper) return deeper
  }
  return null
}

const MAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i
const V4 = /^\d{1,3}(\.\d{1,3}){3}$/
const V6 = /^[0-9a-f:]*:[0-9a-f:.]+$/i
const looksAddr = v => MAC.test(v) || V4.test(v) || V6.test(v)

// The address as the label over the field spells it: "Source: Intel_aa:bb:cc
// (00:1b:21:aa:bb:cc)" where Wireshark knows the vendor of a MAC, and the name on
// its own where that is all the label has. A whole item of the label, so that the
// lane on 10.0.0.1 is not filtered by a field holding 10.0.0.10.
function shows(label, addr) {
  const at = (label || '').indexOf(addr)
  if (at < 0) return false
  const before = label[at - 1], after = label[at + addr.length]
  return (before === undefined || before === ' ' || before === '(') &&
    (after === undefined || after === ' ' || after === ')')
}

// A lane is every frame the address is at either end of, so the clause wants the
// field's both-ends spelling - ip.src becomes ip.addr, wlan.sa becomes wlan.addr.
// Not every field has one, and a Linux cooked capture has no second end to name at
// all, so the spellings are tried against the capture in the order they read best
// and the first one it compiles is the filter.
const BOTH = { src: 'addr', dst: 'addr', sa: 'addr', da: 'addr' }
const OTHER = { src: 'dst', dst: 'src', sa: 'da', da: 'sa' }

function swap(name, to) {
  const parts = name.split('.')
  const at = parts.findIndex(p => to[p])
  return at < 0 ? '' : parts.map((p, i) => i === at ? to[p] : p).join('.')
}

async function ends(hit) {
  const one = hit.name + ' == ' + hit.value
  const both = swap(hit.name, BOTH), other = swap(hit.name, OTHER)
  for (const term of [both && both + ' == ' + hit.value,
    other && one + ' or ' + other + ' == ' + hit.value]) {
    if (term && await compiles(term)) return term
  }
  return one
}

const compiles = term =>
  api('check', { f: S.file, filter: term }).then(res => !!res.ok).catch(() => false)

// A last resort, for an address no field of the frame owned up to: the spellings
// that name their own field wherever they turn up. A resolved name is not one of
// them - it is the name of some field's value and never a value itself - and
// saying so beats a filter that quietly matches nothing.
function guess(a) {
  if (MAC.test(a)) return 'eth.addr == ' + a
  if (V4.test(a)) return 'ip.addr == ' + a
  if (V6.test(a)) return 'ipv6.addr == ' + a
  return ''
}

// Wireshark labels an arrow with a comment the dissector registers for the flow
// graph, which the columns do not carry; Info is the closest thing to it, less the
// part the arrow itself already says.
const trim = info => info.replace(/^(Request|Status): /, '').replace(/\s*\|\s*$/, '').trim()

// The gutter's stamp on a phone, where the cell is FLOWT wide rather than the
// column's own. Only an absolute one is touched, and only the two parts of it a
// diagram does not read by: the date, which is the same on every row of a
// capture, and the digits past the millisecond. A relative or delta time is
// short already and comes through as it is. The list still draws the column
// whole - this is the gutter's own copy of it.
const brief = t => /^\d{4}-/.test(t) ? t.slice(11).replace(/(\.\d{3})\d*Z?$/, '$1') : t

const SELF = 28    // px of stub for a frame addressed to where it came from

function arrow(el, row) {
  const num = el.children[0], time = el.children[1], line = el.children[2]
  const label = line.children[0], left = line.children[1], right = line.children[2]

  time.textContent = row ? (PHONE ? brief(cell(row, 'time')) : cell(row, 'time')) : '…'
  num.textContent = row ? row.n : ''
  line.hidden = !row
  if (!row) return

  const src = cell(row, 'src'), dst = cell(row, 'dst')
  const from = S.node.get(src), to = S.node.get(dst)
  let text = trim(cell(row, 'info'))

  if (from === undefined && to === undefined) {
    // neither end named, so there is no lane to put the frame anywhere near: it keeps
    // its row, as a line of text from the gutter on rather than an arrow, so a
    // filtered set is never quietly short
    line.className = 'fa plain'
    line.style.left = GUT + 'px'
    line.style.width = Math.max(320, S.width - GUT) + 'px'
    text = [src, dst].filter(Boolean).join(' → ') + '   ' + text
    left.textContent = right.textContent = ''
  } else if (from === undefined || to === undefined) {
    // One end named and the other not, which is every link-layer frame of a Linux
    // cooked capture - what `-i any` and ptcpdump write. SLL carries the address of
    // the host that sent the frame and none at all for the one it went to, so an ARP
    // or an STP has a lane it left and nowhere the capture can say it arrived.
    //
    // A stub off that lane then, rather than a row of text beside the diagram: the
    // lane is the half that is known, and the frame belongs on it. It points the way
    // the frame went, which is the other half of what the capture does say - out of
    // that host, or into it.
    const out = to === undefined
    const at = x(out ? from : to)
    line.className = 'fa stub'
    line.style.left = (out ? at : at - SELF) + 'px'
    line.style.width = SELF + 'px'
    left.textContent = right.textContent = ''
  } else {
    const a = x(from), b = x(to), self = from === to
    const back = self || b < a     // a stub points back at the lifeline it left
    const sp = cell(row, 'sport'), dp = cell(row, 'dport')
    line.className = 'fa' + (back ? ' rev' : '') + (self ? ' self' : '') +
      (!self && sp && dp ? ' ports' : '')
    line.style.left = (self ? a : Math.min(a, b)) + 'px'
    line.style.width = (self ? SELF : Math.abs(b - a)) + 'px'
    // the ports go by which end of the line each is at, not which is the source
    left.textContent = self ? '' : (back ? dp : sp)
    right.textContent = self ? '' : (back ? sp : dp)
  }

  const proto = cell(row, 'proto')
  label.children[0].textContent = proto
  label.children[1].textContent = text
  const held = inner(row)
  label.title = (proto ? proto + ': ' : '') + cell(row, 'info') + (held ? '\n' + held : '')
}

// ------------------------------------------------------------------- detail ---

function show(frame) {
  S.sources = [{ name: 'Frame', bytes: frame.bytes || '' }, ...(frame.ds || [])]
  S.src = 0
  S.mark = null
  const tree = $('#tree')
  tree.textContent = ''
  tree.appendChild(build(frame.tree || []))
  tabs(); bytes()
  $('#field').textContent = ''
  // the panes are worth their space now - and taking it halves the list, so the
  // row this frame came from has to be put back on screen
  const opening = !$('#viewer').classList.contains('picked')
  $('#viewer').classList.add('picked')
  if (opening && S.selIdx >= 0) { reveal(S.selIdx); paint() }
}

// Children are built when a node is first expanded, so a frame with a few
// thousand fields costs only what is on screen.
function build(nodes) {
  const frag = document.createDocumentFragment()
  for (const n of nodes) {
    const el = document.createElement('div')
    el.className = 'n'
    el._n = n

    const label = document.createElement('span')
    label.className = 'l'
    const twisty = document.createElement('span')
    twisty.className = 't'
    twisty.textContent = n.n ? (S.open.has(key(n)) ? '▾' : '▸') : ''
    const text = document.createElement('span')
    text.textContent = n.l || ''
    if (n.g) text.classList.add('g')
    // the severity of the worst expert item anywhere under this node, which
    // Wireshark carries up the tree - so a protocol says one of its fields has
    // something to answer for while the node is still folded. The three the list
    // marks and no more, for the same reason - see SEV.
    if (SEV.indexOf(n.s) >= MARKED) text.dataset.sev = n.s
    label.append(twisty, text)
    el.appendChild(label)

    if (n.n) {
      const kids = document.createElement('div')
      kids.className = 'kids'
      kids.hidden = !S.open.has(key(n))
      if (!kids.hidden) kids.appendChild(build(n.n))
      el.appendChild(kids)
    }
    frag.appendChild(el)
  }
  return frag
}

const key = n => n.fn || n.l || ''

function toggle(el) {
  const kids = el.querySelector(':scope > .kids')
  if (!kids) return
  const shown = !kids.hidden
  if (shown) S.open.delete(key(el._n))
  else {
    S.open.add(key(el._n))
    if (!kids.firstChild) kids.appendChild(build(el._n.n))
  }
  kids.hidden = shown
  el.querySelector(':scope > .l > .t').textContent = shown ? '▸' : '▾'
}

function pick(el) {
  for (const on of document.querySelectorAll('#tree .n.sel')) on.classList.remove('sel')
  el.classList.add('sel')
  const n = el._n
  S.mark = n.h || null
  const src = n.ds === undefined ? 0 : n.ds
  if (src !== S.src && src < S.sources.length) { S.src = src; tabs() }
  bytes(true)

  const field = $('#field')
  field.textContent = n.f || n.fn || ''
  field._filter = n.f || ''
  field.title = n.f ? 'Apply as filter' : ''
}

$('#tree').addEventListener('click', e => {
  const el = e.target.closest('.n')
  if (!el) return
  if (e.target.classList.contains('t')) toggle(el)
  else pick(el)
})
$('#tree').addEventListener('dblclick', e => {
  const el = e.target.closest('.n')
  if (el) toggle(el)
})
$('footer').addEventListener('click', e => {
  // On the capture list the bar is the drop hint, so clicking it offers the
  // same thing a drop does - unless captures have been picked out, when it is
  // their open button and Clear is the one part of it with a click of its own.
  // In the viewer it is the picked field's filter.
  if (!$('#files').hidden) {
    if (e.target === $('#unpick')) { pickNone(); return }
    if (picking()) { openCapture(refOf(S.picked)); return }
    if (e.target !== $('#pick')) $('#pick').click()
    return
  }
  if ($('#field')._filter) filter($('#field')._filter)
})

// -------------------------------------------------------------------- bytes ---

// Narrow enough and the byte pane has no room beside the tree, so it takes turns
// with it instead of going away: which of the two is showing is this, and the
// switch above them is what sets it (style.css shows that switch at the same
// width the panes stop fitting side by side). Kept across frames - a pane picked
// once is the one the next frame is read in - and not remembered any further than
// the session, being where the page is rather than how it looks.
let PANE = 'tree'
// ...and whether the bytes are on screen at all, which is what bytes() builds for:
// a pane nothing can see is a hex dump of a reassembled stream built for nobody.
const hexOn = () => !NARROW || PANE === 'bytes'

function panes(pick) {
  PANE = pick
  $('#panes').classList.toggle('bytes', pick === 'bytes')
  for (const b of $('#panetabs').children) b.classList.toggle('on', b.dataset.pane === pick)
  if (pick === 'bytes') bytes(true)   // the pane it was hidden for was not built
}

for (const [pane, what] of [['tree', 'Detail'], ['bytes', 'Bytes']]) {
  const b = document.createElement('button')
  b.textContent = what
  b.dataset.pane = pane
  b.className = pane === PANE ? 'on' : ''
  b.onclick = () => panes(pane)
  $('#panetabs').appendChild(b)
}

function tabs() {
  const bar = $('#sources')
  bar.textContent = ''
  if (S.sources.length < 2) return          // nothing to choose between
  S.sources.forEach((src, i) => {
    const b = document.createElement('button')
    b.textContent = src.name || 'source ' + i
    b.className = i === S.src ? 'on' : ''
    b.onclick = () => { S.src = i; tabs(); bytes() }
    bar.appendChild(b)
  })
}

function decode(b64) {
  if (!b64) return new Uint8Array(0)
  const bin = atob(b64), out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'))
const CHAR = Array.from({ length: 256 }, (_, i) => {
  if (i < 0x20 || i > 0x7e) return '.'
  return i === 60 ? '&lt;' : i === 62 ? '&gt;' : i === 38 ? '&amp;' : String.fromCharCode(i)
})

function bytes(scroll) {
  if (!hexOn()) { hex.textContent = ''; return }
  // Sixteen to a line is 72 characters, which is what the pane is worth where it
  // has one (see style.css) - and 520px, which no phone has. Eight is 39, so the
  // dump fits the screen it is on and the ASCII column can be read without the
  // pane being panned to reach it. The offsets say which line is which either way.
  const wid = PHONE ? 8 : 16, mid = wid / 2 - 1
  const data = decode((S.sources[S.src] || {}).bytes)
  const from = S.mark ? S.mark[0] : -1, to = S.mark ? S.mark[0] + S.mark[1] : -1
  const out = []
  for (let off = 0; off < data.length; off += wid) {
    let h = '', a = '', open = false
    for (let i = 0; i < wid; i++) {
      const p = off + i
      if (p >= data.length) {
        if (open) { h += '</b>'; a += '</b>'; open = false }
        h += i === mid ? '    ' : '   '
        continue
      }
      const on = p >= from && p < to
      if (on && !open) { h += '<b>'; a += '<b>'; open = true }
      if (!on && open) { h += '</b>'; a += '</b>'; open = false }
      h += HEX[data[p]] + (i === mid ? '  ' : ' ')
      a += CHAR[data[p]]
    }
    if (open) { h += '</b>'; a += '</b>' }
    out.push('<i>' + off.toString(16).padStart(4, '0') + '</i>  ' + h + ' ' + a)
  }
  hex.innerHTML = out.join('\n')
  if (scroll) hex.querySelector('b')?.scrollIntoView({ block: 'nearest' })
}

// ------------------------------------------------------------------- filter ---

async function filter(text) {
  text = (text || '').trim()
  $('#filter').value = text
  closeComplete()
  note('Filtering…')
  if (text) {
    const use = await compile(text)
    if (!use.ok) { $('#filter').classList.add('bad'); note(use.err); return }
    // ...and the quotes it put in are left in the box: they are the filter from
    // here on - the URL keeps them, the next edit starts from them, and hiding a
    // lane wraps them - so what is filtered on is never something unwritten
    text = $('#filter').value = use.text
  }
  $('#filter').classList.remove('bad')
  S.filter = text
  rewind()
  await fetchPage(0)   // the slow part: sharkd builds the whole-file match bitmap here
  if (S.pages.has(0)) note('')   // otherwise fetchPage() already left its own error in #msg
}

function rewind() {
  S.pages.clear()
  S.selIdx = -1
  S.count = S.filter ? 0 : S.total
  S.end = !S.filter
  S.nodes = []          // the node columns are the pages', and those are gone
  S.node.clear()
  unlane()
  list.scrollTop = 0
  list.scrollLeft = 0   // ...and the lane it was scrolled along to is not there either
  $('#tree').textContent = ''
  hex.textContent = ''
  $('#sources').textContent = ''
  $('#field').textContent = ''
  $('#viewer').classList.remove('picked')
  counter(); sync(); paint()
}

// Enter is where a filter ends on a phone: there is nowhere to click away to,
// so the box hands the focus back on submit and the soft keyboard goes down
// with it, uncovering the rows the filter just picked. A pointer that can hover
// is a desktop, where the bar is expected to stay focused for the next edit.
const noHover = matchMedia('(hover: none)')
$('#filterbar').addEventListener('submit', e => {
  e.preventDefault()
  if (noHover.matches) $('#filter').blur()   // before the round-trip below, not after it
  if (S.file) filter($('#filter').value)
})
// Wireshark's own filter bar checks as you type and offers field names for
// whatever identifier the caret sits in - the same two sharkd calls filter()
// makes on submit, just fired live and against a token instead of the line.
let liveTimer, compAsked = null
let compItems = [], compIdx = -1

$('#filter').addEventListener('input', () => {
  if (!S.file) { find($('#filter').value); return }
  clearTimeout(liveTimer)
  liveTimer = setTimeout(liveCheck, 150)
})

async function liveCheck() {
  const text = $('#filter').value
  if (!text.trim()) { $('#filter').classList.remove('bad'); closeComplete(); return }
  await validate(text)
  complete(fieldAt(text, $('#filter').selectionStart))
}

async function validate(text) {
  const use = await compile(text)
  if ($('#filter').value === text) $('#filter').classList.toggle('bad', !use.ok)
}

// A display filter types a bare value by how it is spelled and not by the field
// it is compared against, so a string field with a number for a value is a filter
// Wireshark rejects: `ims.id == 001010000000001` is an octal integer to the
// lexer - 69793218561 - and an integer is not a string. An IMPI or an IMPU fares
// worse: the `@` is not a character a bare value may hold at all.
//
// Quoting is Wireshark's own answer to both, and nothing in a plugin can change
// that - a field says it holds a string (plugins/ims.lua does), and what a value
// means is the filter engine's to decide - so the box puts the quotes in. It runs
// only on a filter that does not compile as typed: one that does is sent exactly
// as it was written, and the rewrite has to compile in its turn or it is dropped
// and the error the filter earned is the error shown.
async function compile(text) {
  const check = await api('check', { f: S.file, filter: text }).catch(err => ({ ok: false, err: err.message }))
  if (check.ok) return { ok: true, text }
  const fixed = await requote(text)
  if (fixed === text) return { ok: false, text, err: check.err }
  const retry = await api('check', { f: S.file, filter: fixed }).catch(() => ({ ok: false }))
  return retry.ok ? { ok: true, text: fixed } : { ok: false, text, err: check.err }
}

// Wireshark's lexer in miniature: quoted strings and regexes whole - a value the
// box wrote quotes around once is not one to write them around again - then the
// operators and the punctuation, and a bare value is everything up to the next of
// those. A `/` is left out of a bare value on purpose: `matches /^INVITE/` is a
// regex and not a value, and a value with a slash in it is the rarer of the two,
// so it stays the caller's to quote.
const PIECE = /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\/(?:\\.|[^/\\])*\/|&&|\|\||==|!=|>=|<=|[(){}[\],<>~!=]|[^\s(){}[\],"'/&|<>~!=]+/g
const COMPARE = new Set(['==', '!=', '>=', '<=', '>', '<', '~',
  'eq', 'ne', 'gt', 'lt', 'ge', 'le', 'contains', 'matches', 'in'])
const bare = t => !'"\'/(){}[],<>~!=&|'.includes(t[0])

// The same filter with a quoted value wherever one is compared against a field
// that takes a string. Spliced into the text rather than rebuilt from the pieces,
// so the spacing and everything else is the line as it was typed.
async function requote(text) {
  const pieces = [...text.matchAll(PIECE)]
  const found = []          // the bare values, with the field each is compared against
  let field = '', many = false
  for (let i = 0; i < pieces.length; i++) {
    const t = pieces[i][0], op = t.toLowerCase()
    if (COMPARE.has(op)) {
      const left = i > 0 ? pieces[i - 1][0] : ''
      field = bare(left) ? left : ''
      many = op === 'in'    // `ims.id in {a, b}` is a value per member of the set
      continue
    }
    if (!field) continue
    if (many && (t === '{' || t === ',')) continue
    if (bare(t)) found.push({ at: pieces[i], field })
    if (!many || !bare(t)) field = ''   // anything else closes the set, `}` included
  }
  if (!found.length) return text

  // which of those fields take a string at all: sharkd is asked, since the answer
  // is the field's type and the types are Wireshark's own
  const fields = [...new Set(found.map(f => f.field))]
  const takes = new Map(await Promise.all(fields.map(async f => [f, await takesString(f)])))

  let out = '', end = 0
  for (const { at, field: f } of found) {
    if (!takes.get(f)) continue
    out += text.slice(end, at.index) + '"' + at[0].replace(/["\\]/g, '\\$&') + '"'
    end = at.index + at[0].length
  }
  return end ? out + text.slice(end) : text
}

// Whether a field compares against a string, which is what says quoting its value
// could help rather than hurt - `frame.number > "10"` is as rejected as an
// unquoted identity is. Asked once and kept: a field's type outlives every filter
// typed against it.
const stringy = new Map()
function takesString(field) {
  if (!stringy.has(field)) {
    stringy.set(field, api('check', { f: S.file, filter: field + ' == "webshark"' })
      .then(res => !!res.ok).catch(() => false))
  }
  return stringy.get(field)
}

// the dotted identifier ending at the caret - "sip.st and ip" completes "ip",
// not the clause already typed before it
const fieldAt = (text, pos) => (text.slice(0, pos).match(/[\w.-]+$/) || [''])[0]

async function complete(field) {
  if (!field) { closeComplete(); return }
  const asked = compAsked = field
  const res = await api('complete', { f: S.file, field }).catch(() => null)
  if (!res || asked !== compAsked) return   // the caret moved on while this was out
  compItems = (res.field || []).slice(0, 20)
  compIdx = -1
  const box = $('#complete')
  box.textContent = ''
  for (const f of compItems) {
    const li = document.createElement('li')
    li._f = f
    const name = document.createElement('span')
    name.textContent = f.f
    const desc = document.createElement('span')
    desc.textContent = f.n
    li.append(name, desc)
    box.appendChild(li)
  }
  box.hidden = compItems.length === 0
}

function closeComplete() {
  clearTimeout(liveTimer)   // else the check still pending reopens what this closed
  compItems = []; compIdx = -1; compAsked = null
  $('#complete').hidden = true
}

function highlight(i) {
  for (const li of $('#complete').children) li.classList.remove('sel')
  compIdx = i
  const li = $('#complete').children[i]
  li.classList.add('sel')
  li.scrollIntoView({ block: 'nearest' })
}

// replaces the token under the caret with the picked field, not the whole
// filter - there may be a clause typed either side of it already
function pickComplete(li) {
  if (!li) return
  const input = $('#filter'), pos = input.selectionStart
  const start = pos - fieldAt(input.value, pos).length
  input.value = input.value.slice(0, start) + li._f.f + input.value.slice(pos)
  closeComplete()
  input.focus()
  input.setSelectionRange(start + li._f.f.length, start + li._f.f.length)
  validate(input.value)   // not liveCheck() - the caret sits right after a field
  // name, which would otherwise reopen the dropdown this pick just closed
}

$('#complete').addEventListener('mousedown', e => e.preventDefault())  // stay focused on #filter
$('#complete').addEventListener('click', e => pickComplete(e.target.closest('li')))
$('#filter').addEventListener('blur', closeComplete)

$('#filter').addEventListener('keydown', e => {
  if ($('#complete').hidden) return
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault()
    const dir = e.key === 'ArrowDown' ? 1 : -1
    highlight(compIdx < 0 ? (dir > 0 ? 0 : compItems.length - 1) : (compIdx + dir + compItems.length) % compItems.length)
  } else if (e.key === 'Tab' || (e.key === 'Enter' && compIdx >= 0)) {
    e.preventDefault()
    pickComplete($('#complete').children[compIdx < 0 ? 0 : compIdx])
  } else if (e.key === 'Escape') {
    e.stopPropagation()   // close the dropdown, not the whole filter - see the keydown handler below
    closeComplete()
  }
})

// -------------------------------------------------------------------- files ---

// What the server opens: one capture, or several read as one - their names
// joined by commas, which no capture name can hold, and sorted, which is the
// order the server puts them back in (parts() in src/merge.go). So the same set
// is the same reference however it was picked, and the same sharkd.
const refOf = names => [...names].sort().join(',')
const namesIn = ref => ref.split(',')

const human = n => n < 1024 ? n + ' B'
  : n < 1048576 ? (n / 1024).toFixed(0) + ' kB'
  : n < 1073741824 ? (n / 1048576).toFixed(1) + ' MB'
  : (n / 1073741824).toFixed(1) + ' GB'

async function files() {
  S.file = null
  S.st = null
  $('#viewer').hidden = true
  $('#files').hidden = false
  for (const sel of ['#back', '#mode']) $(sel).hidden = true
  $('#brand').hidden = false
  $('#name').hidden = true
  $('#filter').placeholder = 'filter captures: name, protocol, time'
  $('#filter').value = S.find
  $('#filter').classList.remove('bad')
  closeComplete()
  const field = $('#field')
  field.textContent = ''
  field._filter = ''
  field.title = ''
  sync()

  S.caps = await api('captures').catch(err => { note(err.message); return [] })
  // a capture picked before it was deleted is no longer one of them
  for (const name of S.picked) {
    if (!S.caps.some(c => c.name === name)) S.picked.delete(name)
  }
  drawFiles()
  scanAll()
}

let waited = ''      // the last thing drawFiles() put in the footer, if anything
let fileTerms = []   // the parsed box, kept for filesDraw()'s protocol highlighting

// The rows the filter leaves, and their verdicts - 'maybe' becomes the .tent
// class filesDraw() paints them with. Everything about a capture is already here
// except its protocols, which arrive one file at a time (scanAll), so this is
// called again on each of them; only the pool filesDraw() recycles ever touches
// the DOM; a directory of thousands of captures costs the same few rows of it
// that a screenful does.
function drawFiles() {
  fileTerms = parseFind(S.find)
  S.filed = []
  let waiting = 0
  for (const c of S.caps) {
    const verdict = matches(c, fileTerms)
    if (!verdict) continue
    if (verdict === 'maybe') waiting++
    S.filed.push({ c, tent: verdict === 'maybe' })
  }
  pickbar()
  $('#empty').hidden = S.filed.length > 0
  $('#empty').textContent = !S.caps.length ? 'No captures yet.'
    : 'No capture matches that.'
  counter()
  // rows still waiting for their protocols are shown rather than hidden, so say
  // why the list may yet get shorter - and leave any other message alone, an
  // upload or a capture that would not open having more to say than this does
  const say = waiting && fileTerms.length ? 'still reading ' + waiting + ' of them' : ''
  if (say || waited) note(say)
  waited = say
}

// A slot's shape never changes across rows, so it is built once and only its
// text and links are touched on redraw - the same split as the packet list's
// slot()/draw().
function fileSlot(i) {
  while (fileSlots.length <= i) {
    const el = document.createElement('div')
    el.className = 'caprow'
    const mark = span('k')
    const name = span('n'), size = span('s'), at = span('t'), protos = span('p'), action = span('a')
    name.appendChild(document.createElement('a')).className = 'open'
    action.appendChild(document.createElement('a')).className = 'dl'
    action.firstChild.textContent = 'download'
    el.append(mark, name, size, at, protos, action)
    filecanvas.appendChild(el)
    fileSlots.push(el)
  }
  return fileSlots[i]
}

function filesDraw() {
  CROW = parseFloat(getComputedStyle($('#files')).getPropertyValue('--row')) || CROW
  filecanvas.style.height = (S.filed.length * CROW) + 'px'
  const first = Math.max(0, Math.floor(filelist.scrollTop / CROW) - OVER)
  const upto = Math.min(S.filed.length, first + Math.ceil(filelist.clientHeight / CROW) + OVER * 2)

  let s = 0
  for (let i = first; i < upto; i++, s++) {
    const { c, tent } = S.filed[i], el = fileSlot(s)
    el.style.top = (i * CROW) + 'px'
    el.hidden = false
    el.classList.toggle('tent', tent)
    // which row this slot is holding, for the click and the press that pick it:
    // the pool recycles the element, so the index cannot be closed over
    el.dataset.i = i
    const on = S.picked.has(c.name)
    el.classList.toggle('on', on)
    el.children[0].textContent = on ? '\u2713' : ''

    const link = el.querySelector('a.open')
    link.textContent = c.name
    link.title = c.name

    el.children[2].textContent = human(c.size)

    const at = el.children[3]
    at.textContent = captured(c)
    at.title = spelt(c)

    const protos = el.children[4]
    protos.title = !c.protos ? 'still reading'
      : (c.partial ? c.protos.length + ' protocols in the first frames of the capture'
        : c.protos.length + ' protocols') + '\n' + c.protos.join(' ')
    protos.classList.toggle('some', !!c.partial)
    protos.textContent = ''
    if (!c.protos) protos.textContent = '…'
    else {
      // The list is the server's order - what the capture holds the most of
      // first - except for whatever the filter matched, which goes to the front
      // marked: the column is long enough to be cut off, and the reason a row is
      // on the list is the part of it worth seeing.
      const words = fileTerms.filter(t => !t.neg && t.word && (!t.facet || t.facet === 'proto'))
      const hit = c.protos.filter(p => words.some(t => named(p, t.word)))
      for (const p of hit) protos.append(span('hit', p), document.createTextNode(' '))
      protos.append(c.protos.filter(p => !hit.includes(p)).join(' '))
    }

    el.querySelector('a.dl').href = 'api/file?f=' + encodeURIComponent(c.name)
  }
  for (; s < fileSlots.length; s++) fileSlots[s].hidden = true
}

let fqueued = false
function filesPaint() {
  if (fqueued) return
  fqueued = true
  requestAnimationFrame(() => { fqueued = false; filesDraw() })
}

// One listener for the whole pool, since the rows themselves are recycled: the
// whole row opens the capture, and a click on the download link is left to the
// browser. The row rather than the name it starts with, which is a line of text
// tall - a target a mouse can hit and a finger cannot, the rest of the row
// having looked just as clickable and done nothing.
//
// ...unless captures have been picked out, which is the other thing a click on a
// row does - see picking below.
filecanvas.addEventListener('click', e => {
  if (e.target.closest('a.dl')) return
  const row = e.target.closest('.caprow')
  if (!row) return
  if (pressed) { pressed = false; return }   // a long press has already had this
  const i = +row.dataset.i
  if (e.shiftKey) pickRow(i, 'through')
  else if (e.ctrlKey || e.metaKey || picking()) pickRow(i)
  else openCapture(S.filed[i].c.name)
})
filelist.addEventListener('scroll', filesPaint, { passive: true })
new ResizeObserver(filesPaint).observe(filelist)

// ------------------------------------------------------- picking several ---

// Two sides of the same call are two captures, and reading them against each
// other is what a merge is for: the picked ones are opened as one reference
// (refOf), which the server merges by timestamp into the one file sharkd loads -
// so they are one packet list, one display filter and one sequence diagram. See
// src/merge.go.
//
// The list is a list of captures to open until the first one is picked, and a
// list to pick from after that: nothing is on a row, and no column is under it,
// until ctrl-click (cmd-click), shift-click or - where there are no modifiers to
// press - a long press says that is what this is. From there a plain click picks
// too, and the way back out is the footer's Clear, Escape, or the back gesture
// that reaches the same place (pop()).
let anchor = -1        // the row a shift-click reaches back to
let pressed = false    // ...and whether a long press has just picked one

const picking = () => S.picked.size > 0

function pickRow(i, how) {
  const c = S.filed[i] && S.filed[i].c
  if (!c) return
  // a shift-click takes everything between the two, which is the run of captures
  // an eye picked out of the list; a plain one is the row it is on
  if (how === 'through' && anchor >= 0 && anchor < S.filed.length) {
    const [from, to] = anchor < i ? [anchor, i] : [i, anchor]
    for (let j = from; j <= to; j++) S.picked.add(S.filed[j].c.name)
  } else {
    if (S.picked.has(c.name)) S.picked.delete(c.name)
    else S.picked.add(c.name)
    anchor = i
  }
  pickbar()
}

function pickNone() {
  S.picked.clear()
  anchor = -1
  pickbar()
}

// The marks on the rows and the offer in the footer, which is the whole of what
// picking looks like: the bar is the list's open button either way (see the
// footer's own listener), so what changes is what it says it will open.
function pickbar() {
  const n = S.picked.size
  $('#files').classList.toggle('picking', n > 0)
  $('#picks').hidden = $('#unpick').hidden = !n
  // one capture picked is still a capture to open by name: what the bar offers
  // is what opening it will do, which for several is a merge and worth saying
  $('#picks').textContent = n === 1 ? 'Open ' + [...S.picked][0]
    : 'Open ' + n + ' captures as one'
  $('#picks').title = n < 2 ? ''
    : 'Read as one capture, their frames in time order:\n' + [...S.picked].sort().join('\n')
  filesPaint()
}

// A touch has no modifier to hold, so the press itself is what picks: long
// enough to be meant, and let go of the moment it turns into the scroll this
// list is mostly touched for. The click that follows the press is the one the
// row would have opened on, which is what `pressed` swallows.
let press = null, held = null
filecanvas.addEventListener('pointerdown', e => {
  pressed = false
  if (e.pointerType === 'mouse' || e.target.closest('a.dl')) return
  const row = e.target.closest('.caprow')
  if (!row) return
  const i = +row.dataset.i
  held = { x: e.clientX, y: e.clientY }
  press = setTimeout(() => { press = null; pressed = true; pickRow(i) }, 450)
})
filecanvas.addEventListener('pointermove', e => {
  if (press && Math.hypot(e.clientX - held.x, e.clientY - held.y) > 10) letgo()
}, { passive: true })
for (const done of ['pointerup', 'pointercancel', 'pointerleave']) {
  filecanvas.addEventListener(done, letgo)
}
function letgo() { clearTimeout(press); press = null }
// the press has picked the row; the menu the browser would put over it on the
// same gesture is not what was being asked for
filecanvas.addEventListener('contextmenu', e => { if (pressed) e.preventDefault() })

// Protocols are a dissection, so the server does not put them in the listing -
// they are asked for a file at a time and the list is redrawn as each lands. The
// server scans one capture at a time whatever this does, so there is nothing to
// gain by asking for several at once, and a lot to lose in a directory of them.
let scanning = 0
async function scanAll() {
  const run = ++scanning
  for (const c of S.caps) {
    // a capture being read is worth more of the machine than the rest of the
    // directory is; coming back to the list starts this again, cache and all
    if (S.file || run !== scanning) return
    if (c.protos) continue
    const res = await api('scan', { f: c.name }).catch(() => null)
    if (run !== scanning) return       // back on the list again, with another set
    if (res) { c.protos = res.protos; c.partial = res.partial; drawFiles() }
  }
}

// ------------------------------------------------------- filtering the list ---

// One word of the box is one term, and a capture has to satisfy all of them.
// A term is matched against the file's name, its protocols, and the stretch of
// time its frames were captured over - whichever of the three it looks like:
//
//	pcscf          the name, a protocol, or the timestamp as text
//	diameter       ...which for a protocol is the name a display filter uses
//	proto:sip      only a protocol, for a word that is also a file name
//	2026-08-14     a capture with frames on that day
//	>2h            ...in the last two hours, and <2h for older than that
//	>10:00         ...after ten this morning
//	after:9:30     the same thing spelled out, and before: for the other end
//	-tls           captures without it
//
// The facets are there for the ambiguous cases; nothing has to be learnt to use
// the box, which is the point of it being one box.
function parseFind(text) {
  return (text || '').trim().split(/\s+/).filter(Boolean).map(word => {
    let neg = false
    if (word.length > 1 && word[0] === '-') { neg = true; word = word.slice(1) }
    let facet = '', op = ''
    const f = word.match(/^(name|proto|time|after|before):(.*)$/i)
    if (f) { facet = f[1].toLowerCase(); word = f[2] }
    if (facet === 'after') { facet = 'time'; op = '>' }
    if (facet === 'before') { facet = 'time'; op = '<' }
    const o = word.match(/^(>=|<=|>|<)(.*)$/)
    if (o) { op = o[1]; word = o[2] }
    return { neg, facet, op, word: word.toLowerCase(), at: moment(word) }
  })
}

// true, false, or 'maybe' - a capture whose protocols have not arrived yet cannot
// answer a term about them, and is left on the list rather than hidden: the scan
// may be about to match it, and a row that appears is less confusing than one
// that silently was not there.
function matches(c, terms) {
  let sure = true
  for (const t of terms) {
    const hit = term(c, t)
    if (hit === null) { sure = false; continue }
    if (hit === t.neg) return false
  }
  return sure ? true : 'maybe'
}

function term(c, t) {
  // a term still being typed - `proto:`, `>` - narrows nothing rather than
  // hiding the list until it is finished
  if (!t.word && !t.at) return true
  if (t.facet === 'time' || t.op) return t.at ? overlaps(c, t) : false
  if (t.facet === 'name') return c.name.toLowerCase().includes(t.word)
  if (t.facet === 'proto') return c.protos ? proto(c, t.word) : null
  // a bare word: whatever it does match. The name and the time are known, so a
  // hit on either settles it; only a miss has to wait for the protocols.
  if (c.name.toLowerCase().includes(t.word)) return true
  if (captured(c).toLowerCase().includes(t.word)) return true
  if (t.at && overlaps(c, t)) return true
  return c.protos ? proto(c, t.word) : null
}

// A protocol is matched on a word of its name, not on any run of letters inside
// it: `esp` is the security protocol and not the tail of Redis's `resp`, while
// `malformed` still finds `_ws.malformed` and `text` finds `data-text-lines`.
// File names stay a plain substring match - those are arbitrary, and half a word
// out of the middle of one is a reasonable thing to type.
const named = (p, word) => p.split(/[-._]/).some(part => part.startsWith(word))
const proto = (c, word) => c.protos.some(p => named(p, word))

// A capture covers a stretch of time and so does a term - `2026-08-14` is a day,
// `>2h` everything since two hours ago - so the two are compared as ranges.
// Without an operator the question is whether they overlap at all.
function overlaps(c, t) {
  const [from, to] = taken(c)
  if (!from) return false
  if (t.op === '>' || t.op === '>=') return to >= t.at.from
  if (t.op === '<' || t.op === '<=') return from <= t.at.to
  return from <= t.at.to && to >= t.at.from
}

// When a capture's frames were taken: its own clock where it has one, and the
// file's mtime only where it says nothing at all.
//
// A capture with a first frame and no last - a classic pcap, which cannot be read
// backwards, or one still being written, whose last block is half there - counts
// as the instant it started rather than as running until the file was last
// touched. The mtime of a pcap copied in from somewhere is the day it was copied,
// which would put a capture from January in this afternoon's results; and a filter
// that disagrees with the time on the row it hides is worse than one that reads
// the start of a live capture as the whole of it.
const taken = c => c.first ? [c.first, c.last || c.first] : [c.mtime, c.mtime]

const pad = n => String(n).padStart(2, '0')
const stamp = ms => {
  const d = new Date(ms)
  return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
    ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds())
}

// what the Captured column says, and what a bare word is matched against. The
// stretch is only shown when both ends of it are the capture's own: with the
// file's mtime standing in for one, it would be the age of the file rather than
// the length of the capture - months, for a pcap kept around since January.
function captured(c) {
  const [from, to] = taken(c)
  if (!from) return ''
  const both = c.first && c.last
  return (c.first ? '' : '~') + stamp(from) +
    (both && to > from + 1000 ? '  +' + lasted(to - from) : '')
}

// ...and the same thing in full, with what is missing said rather than implied,
// for the cell's tooltip
function spelt(c) {
  const [from, to] = taken(c)
  if (!from) return ''
  if (!c.first) return stamp(from) + '\nthe capture does not say when, so this is the file\'s own time'
  if (!c.last) return stamp(from) + '\nits first frame; the file does not say where the last one is'
  return stamp(from) + ' → ' + stamp(to)
}

const lasted = ms => ms < 60000 ? (ms / 1000).toFixed(0) + 's'
  : ms < 3600000 ? Math.round(ms / 60000) + 'm'
  : ms < 86400000 ? (ms / 3600000).toFixed(1) + 'h'
  : Math.round(ms / 86400000) + 'd'

const DAY = 86400000
const UNIT = { m: 60000, h: 3600000, d: DAY, w: 7 * DAY }

// A word as the stretch of time it names, or null if it names none. Only the
// spellings a person types into a search box: a date, a clock time, a keyword, or
// an age.
function moment(word) {
  const day = (y, m, d) => { const at = new Date(y, m, d).getTime(); return { from: at, to: at + DAY - 1 } }
  const now = Date.now()
  const today = new Date()

  if (word === 'today') return day(today.getFullYear(), today.getMonth(), today.getDate())
  if (word === 'yesterday') return day(today.getFullYear(), today.getMonth(), today.getDate() - 1)
  if (word === 'now') return { from: now, to: now }

  // 30m, 2h, 7d, 2w - an age rather than a time, so it moves with the clock
  const ago = word.match(/^(\d+(?:\.\d+)?)([mhdw])$/)
  if (ago) return { from: now - ago[1] * UNIT[ago[2]], to: now }

  // a date, with or without a clock time after it. The day, the minute or the
  // second - whatever was written is how wide the range is.
  const date = word.match(/^(\d{4})-(\d{2})-(\d{2})(?:[t_](\d{1,2}):(\d{2})(?::(\d{2}))?)?$/)
  if (date) {
    const [, y, mo, d, h, mi, s] = date
    if (h === undefined) return day(+y, mo - 1, +d)
    const at = new Date(+y, mo - 1, +d, +h, +mi, +(s || 0)).getTime()
    return { from: at, to: at + (s === undefined ? 60000 : 1000) - 1 }
  }

  // a clock time on its own is today's
  const clock = word.match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/)
  if (clock) {
    const [, h, mi, s] = clock
    const at = new Date(today.getFullYear(), today.getMonth(), today.getDate(), +h, +mi, +(s || 0)).getTime()
    return { from: at, to: at + (s === undefined ? 60000 : 1000) - 1 }
  }
  return null
}

function find(text) {
  S.find = text
  if ($('#filter').value !== text) $('#filter').value = text
  anchor = -1   // the row it named is not the row that index is now
  drawFiles()
  sync()
}

// The row index of a frame number, for the link that carries one: with a filter the
// two are not the same number, and the only thing that knows the difference is the
// rows themselves - so the pages it could be in are fetched until it turns up.
// Frames come in capture order, so a page reaching past the wanted number settles
// it: the frame is not in the filtered set, and neither is a row for it.
async function locate(num) {
  for (let p = 0; ; p++) {
    const pending = S.pages.get(p)
    if (pending === undefined) await fetchPage(p)
    else if (typeof pending.then === 'function') await pending
    const page = S.pages.get(p)
    if (!Array.isArray(page)) return -1            // the fetch failed and said so
    const at = page.findIndex(row => row.n === num)
    if (at >= 0) return p * PAGE + at
    if (page.length < PAGE) return -1              // that page was the end of the set
    if (page[page.length - 1].n > num) return -1    // ...or already past the frame
  }
}

async function openCapture(file, want, num, as) {
  const names = namesIn(file)
  note(names.length > 1 ? 'Merging ' + names.length + ' captures …' : 'Opening ' + file + ' …')
  let st
  try {
    st = await api('status', { f: file })
  } catch (err) {
    note(err.message); files(); return
  }
  S.file = file
  S.total = st.frames
  S.filter = want || ''
  S.order = []   // another capture, another set of addresses to arrange
  fit(st)        // ...and its own width for the Time column, whichever is drawn
  columns(st)
  gutter()       // which the diagram's gutter is too, and it was sized before
                 // there was a capture to size it to

  $('#files').hidden = true
  $('#viewer').hidden = false
  $('#back').hidden = false
  $('#brand').hidden = true
  $('#name').hidden = false
  // the reference rather than st.filename, which for a merge is the temp file
  // the server made of them and names nothing the list ever showed
  $('#name').textContent = names.map(n => n.replace(/\.[^.]+$/, '')).join(' + ')
  $('#name').title = names.length < 2 ? ''
    : names.length + ' captures read as one, their frames in time order:\n' + names.join('\n')
  $('#filter').placeholder = 'display filter'
  $('#filter').value = S.filter
  note('')
  // the viewer is on screen before the view is built, so the flow view can lay
  // its columns out against a width the window really has
  view(as === 'flow' && !$('#mode').hidden ? 'flow' : 'list')
  rewind()

  // a frame number is a row index of its own only while nothing is filtered
  if (num) {
    const at = S.filter ? await locate(num) : num - 1
    if (at >= 0) { reveal(at); select(at) }
  }
}

// Back to the list, which is also the end of the capture as far as the server is
// concerned - sharkd holds one file at a time, and the next one to be opened is
// not necessarily this one again.
function closeCapture() {
  const file = S.file
  files()
  if (file) api('close', { f: file }, { method: 'POST' }).catch(() => {})
}

$('#back').onclick = closeCapture

// One level back out of wherever the page is, and whether there was one to take:
// the drawer, then the completion list, then the frame being dissected, then the
// capture - the order they stack on screen in, innermost first. The header's own
// button is the middle step of this and nothing else offers the rest, which on a
// phone is the whole of the navigation: Android's back gesture asks for this and
// leaves the app when it answers false (see onBackPressed in MainActivity.kt),
// and Escape is the same thing on a keyboard - see the handler at the end.
function pop() {
  if ($('#settings').classList.contains('on')) { drawer(false); $('#gear').focus(); return true }
  if (!$('#complete').hidden) { closeComplete(); return true }
  if (S.selIdx >= 0) { deselect(); return true }
  if (S.file) { closeCapture(); return true }
  if (picking()) { pickNone(); return true }
  return false   // the capture list is the bottom of it: nothing left to close
}

async function upload(chosen) {
  for (const file of chosen) {
    // The name the server will file it under. It validates one itself - a bare
    // name in its own alphabet, first character included (nameOK in
    // src/main.go) - so a name it would not take is made into one it will,
    // rather than sent on to be rejected: what a file picker hands over on a
    // phone is called "capture (1).pcap" as often as not, and that is no reason
    // to refuse the capture. The Android app does the same to one shared in
    // rather than picked (nameOf in MainActivity.kt).
    let name = file.name.replace(/[^A-Za-z0-9 ._+-]/g, '_').slice(0, 128)
    if (!/^[A-Za-z0-9]/.test(name)) name = ('c' + name).slice(0, 128)
    note('uploading ' + name + ' …')
    try {
      const res = await fetch('api/file?f=' + encodeURIComponent(name), { method: 'POST', body: file })
      const body = await res.json()
      if (body.err) throw new Error(body.err)
    } catch (err) { note(name + ': ' + err.message); return }
  }
  note('')
  files()
}

// the footer's hidden input - the same upload, chosen rather than dropped
$('#pick').addEventListener('change', e => {
  const chosen = [...e.target.files]   // taken before the reset empties the input
  e.target.value = ''                  // so choosing the same file twice still fires
  if (chosen.length) upload(chosen)
})

document.addEventListener('dragover', e => { e.preventDefault(); document.body.classList.add('drop') })
document.addEventListener('dragleave', () => document.body.classList.remove('drop'))
document.addEventListener('drop', e => {
  e.preventDefault()
  document.body.classList.remove('drop')
  if (e.dataTransfer.files.length) upload(e.dataTransfer.files)
})

// ----------------------------------------------------------------- settings ---

// The drawer under the cog: what the UI remembers about how it looks, which is
// nothing the server or the capture has an opinion about. Both settings are a
// list of radios built the same way, and both are kept in localStorage - the
// theme by index.html too, which reads it before the first paint.

// No setting means follow the system, which is what the CSS does on its own; the
// other two states stamp data-theme and are remembered.
const THEMES = [
  { key: 'system', what: 'Follow the system' },
  { key: 'light', what: 'Light' },
  { key: 'dark', what: 'Dark' },
]

function theme(pick) {
  if (pick === 'system') { delete document.documentElement.dataset.theme; localStorage.removeItem('theme') }
  else { document.documentElement.dataset.theme = pick; localStorage.setItem('theme', pick) }
}

// The Time column's shape is a column sharkd already sent - see TIMES - so this
// is no fetch and no reload: the rows on hand carry all three, and this is which
// of them the list draws and the flow view puts in its gutter.
function retime(pick) {
  TIME = pick
  localStorage.setItem('time', pick.key)
  gutter()
  if (!S.st) return
  columns(S.st)   // ...the same columns, read with the new Time slot in them
  unlane()        // the diagram's header and lifelines were laid out for the old gutter
  head()          // the list's title, and the width that one wants
  paint()         // list: cells refill from the swapped column; flow: layout() re-lanes
}

// One group of the drawer: a radio each, the option's own line, and under it the
// sample the time formats want and the themes have no use for. A pick leaves the
// drawer open - the page it changes is behind it, not under it, so the next pick
// is a click away rather than a click and a reopen.
function options(group, list, on, pick) {
  const box = $('#settings .opts[data-group=' + group + ']')
  for (const opt of list) {
    const label = document.createElement('label')
    const radio = document.createElement('input')
    radio.type = 'radio'
    radio.name = group
    radio.checked = opt.key === on.key
    radio.onchange = () => pick(opt)
    label.append(radio, span('what', opt.what))
    if (opt.eg) label.append(span('eg', opt.eg))
    box.append(label)
  }
}

function drawer(open) {
  $('#settings').classList.toggle('on', open)
  $('#gear').setAttribute('aria-expanded', open)
}

$('#gear').onclick = () => drawer(!$('#settings').classList.contains('on'))
// a click anywhere else closes it: the drawer is a menu over the page, not part
// of the header it hangs from
document.addEventListener('mousedown', e => {
  if (!e.target.closest('#settings, #gear')) drawer(false)
})

const themed = THEMES.find(t => t.key === localStorage.getItem('theme')) || THEMES[0]
options('theme', THEMES, themed, opt => theme(opt.key))
options('time', TIMES, TIME, retime)
theme(themed.key)

// -------------------------------------------------------------------- plumb ---

const note = text => { $('#msg').textContent = text }
// counts only - the word would be there in one form and not the other. The two
// pages count different things, and neither is on screen while the other is.
function counter() {
  const el = $('#count')
  if (!S.file) {
    const shown = S.filed.length, all = S.caps.length
    el.textContent = !all ? '' : S.find ? shown + ' of ' + all : String(all)
    el.title = !all ? '' : S.find ? 'matching captures' : 'captures'
    return
  }
  el.textContent = S.filter ? S.count + (S.end ? '' : '+') + ' of ' + S.total : String(S.total)
  el.title = S.filter ? 'matching frames of the capture' : 'frames'
}

// The URL is the whole of the app's state, so a view can be linked or reloaded.
function sync() {
  const p = new URLSearchParams()
  if (S.file) p.set('f', S.file)
  // the capture list's box is kept even with a capture open, so that going back
  // to the list - or reloading into it - lands on the same shortlist
  if (S.find) p.set('s', S.find)
  if (S.filter) p.set('q', S.filter)
  if (S.selIdx >= 0 && S.want) p.set('n', S.want)
  if (S.file && flowing()) p.set('v', 'flow')
  const query = p.toString()
  if ((query ? '#' + query : '') !== location.hash) {
    history.replaceState(null, '', query ? '#' + query : location.pathname)
  }
}

function restore() {
  const p = new URLSearchParams(location.hash.slice(1))
  S.find = p.get('s') || ''
  const f = p.get('f')
  // a reference naming several captures is a set the list picked out, so going
  // back from it - or reloading and then going back - lands on that set still
  // picked, rather than on a list with no sign of what was just being read
  if (f && f.includes(',')) S.picked = new Set(namesIn(f))
  if (f) openCapture(f, p.get('q') || '', +p.get('n') || 0, p.get('v'))
  else files()
}

list.addEventListener('scroll', paint, { passive: true })
// a window crossing the narrow breakpoint changes --row under the list, so the
// rows want re-placing at the new height - and the scroll put back on the frame
// it was on rather than on the pixel, as in view()
new ResizeObserver(() => {
  const top = Math.round(list.scrollTop / ROW)
  const was = PHONE, wasNarrow = NARROW
  if (measure()) {
    canvas.style.height = height() + 'px'
    list.scrollTop = top * ROW
  }
  // ...and crossing the second breakpoint is another set of list columns and
  // another gutter, neither of which is a re-place of the rows: the grid and the
  // widths both come from here (see head() and gutter()), and the diagram's lanes
  // were laid out against the gutter it had. The byte pane comes and goes with the
  // first breakpoint, and what it holds is only built while it can be seen.
  if (PHONE !== was) { gutter(); head(); bytes() }
  else if (NARROW !== wasNarrow) bytes()
  // the collapse to a single row is a resize of its own, and this is the callback
  // it arrives in - so the row it collapsed around is put back under the scrollport
  if (pinned() && S.selIdx >= 0) list.scrollTop = S.selIdx * ROW
  paint()
}).observe(list)

addEventListener('keydown', e => {
  // the drawer first: a radio in it is an INPUT, and the filter box's own Escape
  // below would clear the filter behind an open drawer rather than close it
  if (e.key === 'Escape' && $('#settings').classList.contains('on')) { pop(); return }
  if (e.target.tagName === 'INPUT') {
    if (e.key === 'Escape') { e.target.blur(); S.file ? filter('') : find('') }
    return
  }
  // ...and with no box focused it is the way back out of the view itself, one
  // level a press, which is what the back gesture does on Android - see pop()
  if (e.key === 'Escape') { pop(); return }
  if (e.key === '/' || (e.key === 'f' && (e.ctrlKey || e.metaKey))) { e.preventDefault(); $('#filter').focus(); return }
  if ($('#viewer').hidden) return
  if (e.key === 'v' && !e.ctrlKey && !e.metaKey && !$('#mode').hidden) {
    view(flowing() ? 'list' : 'flow')
    return
  }
  const rows = Math.max(1, Math.floor(list.clientHeight / ROW) - 1)
  const jump = { ArrowDown: 1, ArrowUp: -1, PageDown: rows, PageUp: -rows }[e.key]
  if (jump) { e.preventDefault(); move(jump) }
  else if (e.key === 'Home') { e.preventDefault(); reveal(0); select(0) }
  else if (e.key === 'End' && S.end) { e.preventDefault(); reveal(S.count - 1); select(S.count - 1) }
})

restore()
