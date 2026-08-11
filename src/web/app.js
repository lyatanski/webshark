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

const ROW = 20     // px per list row, matches --row in style.css
const FROW = 28    // ...and per flow row, matches --row as #viewer.flow rescopes it
const CROW = 26    // ...and per capture-list row, matches --row as #files rescopes it
const PAGE = 200   // frames per /api/frames call
const OVER = 8     // rows drawn above and below the viewport
// fixed widths for the columns Wireshark keeps narrow, the rest to the last one -
// which is Info, and wants everything it can get
const WIDE = {
  'No.': 76, Time: 112, Delta: 96, Source: 150,
  Destination: 150, Protocol: 76, Length: 64,
}
const INFO_MIN = 160  // below this the 1fr column would hit 0 and vanish
// the flow view's gutter is the list's own No. and Time columns, so a frame's
// number and time sit in the same place whichever view draws it
const GUT = WIDE['No.'] + WIDE.Time
const LANE = [160, 400]  // node column: spread to fill the window, between these
const NODES = 40   // as many addresses as Wireshark's own flow graph draws

const $ = sel => document.querySelector(sel)

async function api(path, params, init) {
  const res = await fetch('/api/' + path + '?' + new URLSearchParams(params), init)
  const body = await res.json()
  if (body && body.err) throw new Error(body.err)
  return body
}

const S = {
  file: null, filter: '', cols: [], total: 0,
  vis: [],           // row.c indexes the list draws, in order
  ix: {},            // ...and the ones the flow view needs, by name
  view: 'list',
  count: 0,          // frames known to be in the current view
  end: true,         // ...and whether that is all of them
  pages: new Map(),  // page index -> rows, or the Promise fetching them
  selIdx: -1, want: 0,
  nodes: [], node: new Map(),  // flow view: addresses, in the order first seen
  order: [],        // ...or the order they were dragged into, once they have been
  overflow: false,  // ...and whether an address had to be left out of them
  addrs: 0,         // addresses in the whole capture, which is the server's count
  nodeW: LANE[0], width: 0,
  open: new Set(),   // expanded tree nodes by field name, kept across frames
  sources: [], src: 0, mark: null,
  caps: [], find: '',   // the capture list, and the box narrowing it down
  filed: [],            // caps the box leaves, in the order the list draws
}

const list = $('#list'), canvas = $('#canvas'), hex = $('#hex')
const filelist = $('#filelist'), filecanvas = $('#filecanvas')
let slots = []       // recycled row elements
let fileSlots = []   // ...and the capture list's own pool

const flowing = () => S.view === 'flow'
const rowH = () => flowing() ? FROW : ROW

// the list lays its columns out in a grid, the flow view as spans over its gutter;
// these carry the two the views share so .num/.ft can size off the same numbers
$('#viewer').style.setProperty('--numw', WIDE['No.'] + 'px')
$('#viewer').style.setProperty('--timew', WIDE.Time + 'px')

// No. reads as numeric data, so both views set it off from the left-aligned
// text columns.
const numCol = title => title === 'No.' ? 'num' : ''

function span(cls, text) {
  const el = document.createElement('span')
  if (cls) el.className = cls
  if (text) el.textContent = text
  return el
}

// ------------------------------------------------------------- packet list ---

function height() {
  // an unfiltered capture knows its length from `status`; a filtered one only
  // finds out when a page comes back short, so leave a page of room to scroll
  // into until then
  return (S.count + (S.end ? 0 : PAGE)) * rowH()
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
      for (const title of S.cols) el.appendChild(span(numCol(title)))
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
  const H = rowH()
  if (flowing()) layout()
  canvas.style.height = height() + 'px'
  const last = S.count + (S.end ? 0 : PAGE)
  const first = Math.max(0, Math.floor(list.scrollTop / H) - OVER)
  const upto = Math.min(last, first + Math.ceil(list.clientHeight / H) + OVER * 2)

  let s = 0
  for (let i = first; i < upto; i++, s++) {
    const row = rowAt(i), el = slot(s)
    el.style.top = i * H + 'px'
    el.dataset.i = i
    el.hidden = false
    el.classList.toggle('sel', i === S.selIdx)
    el.classList.toggle('gap', !row)
    hue(el, row, i === S.selIdx)
    if (flowing()) arrow(el, row)
    else {
      const cells = el.children
      for (let c = 0; c < S.vis.length; c++) {
        cells[c].textContent = row ? (row.c[S.vis[c]] || '') : (c === 0 ? '…' : '')
      }
    }
  }
  for (; s < slots.length; s++) slots[s].hidden = true
}

function reveal(i) {
  const H = rowH()
  // the height the canvas is *about* to be drawn at: scrolling into a canvas that
  // has not been drawn yet - opening a link with a frame in it - clamps to 0
  canvas.style.height = height() + 'px'
  if (i * H < list.scrollTop) list.scrollTop = i * H
  const bottom = H + (i + 1) * H    // the sticky header owns the first row
  if (bottom - list.scrollTop > list.clientHeight) list.scrollTop = bottom - list.clientHeight
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
// sharkd configured differently, or not at all, still lines up. The ports are the
// two hidden columns the image adds (images/webshark/preferences); without them
// the diagram simply has no ports to label its arrows with.
function columns(st) {
  const info = st.column_info ||
    (st.columns || []).map(title => ({ title, format: '', visible: true }))
  S.vis = info.map((_, i) => i).filter(i => info[i].visible !== false)
  S.cols = S.vis.map(i => info[i].title)

  const at = (fmt, title) => {
    const i = info.findIndex(c => c.format === fmt)
    return i >= 0 ? i : info.findIndex(c => c.title === title)
  }
  S.ix = {
    time: at('%t', 'Time'), src: at('%s', 'Source'), dst: at('%d', 'Destination'),
    sport: at('%uS', 'SrcPort'), dport: at('%uD', 'DstPort'),
    proto: at('%p', 'Protocol'), info: at('%i', 'Info'),
  }
  // with no addresses to put in columns there is no diagram to offer
  $('#mode').hidden = S.ix.src < 0 || S.ix.dst < 0
  if ($('#mode').hidden) S.view = 'list'
}

const cell = (row, name) => (S.ix[name] >= 0 ? row.c[S.ix[name]] : '') || ''

// The list's column titles. The flow view's header is the node columns, which
// only layout() knows the geometry of.
function head() {
  const cols = $('#cols')
  cols.textContent = ''
  cols.style.minWidth = ''
  canvas.style.minWidth = ''
  if (flowing()) return
  for (const title of S.cols) cols.appendChild(span(numCol(title), title))
  $('#viewer').style.setProperty('--grid',
    S.cols.map((c, i) => i === S.cols.length - 1 ? '1fr' : (WIDE[c] || 110) + 'px').join(' '))
  // otherwise a narrow window shrinks the fixed columns' shared box below their
  // own total, and the overflow renders past #cols/canvas with no background to
  // paint it on - the header looks half-transparent and Info can hit 0 width
  const fixed = S.cols.slice(0, -1).reduce((sum, c) => sum + (WIDE[c] || 110), 0)
  const minWidth = fixed + INFO_MIN + 'px'
  cols.style.minWidth = minWidth
  canvas.style.minWidth = minWidth
}

// The views share the pages, the filter and the selection, so switching is a
// repaint - of rows built the other way, hence throwing the slots out.
function view(pick) {
  const top = Math.round(list.scrollTop / rowH())
  S.view = pick
  const button = $('#mode')
  button.classList.toggle('flow', flowing())   // the icon draws whichever view is on
  button.title = flowing()
    ? 'Sequence diagram (click for the packet list)'
    : 'Packet list (click for the sequence diagram)'
  $('#viewer').classList.toggle('flow', flowing())
  for (const el of slots) el.remove()
  slots = []
  unlane()
  head()
  warnFlow()
  canvas.style.height = height() + 'px'   // as in reveal(): rows of another height
  list.scrollTop = top * rowH()           // scroll to the same frame, not the same px
  sync(); paint()
  addresses()   // after the paint: the rows are worth more than the warning is
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

// -------------------------------------------------------- sequence diagram ---

// Wireshark's flow graph: a column per address, a row per frame, an arrow from
// the source's lifeline to the destination's. The columns are the addresses of the
// pages fetched so far - the capture is not read ahead to find the rest, so a
// column appears when a frame using it is first paged in, and the order is the
// order of the frames. Filter first and the diagram is the conversation.
function nodes(rows) {
  let added = false
  for (const row of rows) {
    for (const addr of [cell(row, 'src'), cell(row, 'dst')]) {
      if (!addr || S.node.has(addr)) continue
      if (S.nodes.length < NODES) { S.node.set(addr, S.nodes.length); S.nodes.push(addr); added = true }
      else S.overflow = true
    }
  }
  if (added) arrange()   // a new column goes where the arranged ones leave it
  warnFlow()
}

// Too many addresses for the diagram to draw them all: the frames using the ones
// past NODES keep their rows, as plain text rather than arrows (see arrow()), and a
// filter narrowing the capture down is the way back to a real diagram.
//
// Two things know about it. addresses() has asked the server for the whole
// capture's count, so the warning is up before a row that overflows is anywhere
// near the screen; S.overflow is the node list filling up as pages arrive, which is
// the backstop for what that count leaves out - the MAC of a frame with no IP.
function warnFlow() {
  const over = S.addrs > NODES
  $('#flowwarn').hidden = !(flowing() && (over || S.overflow))
  $('#flowmsg').textContent = over
    ? S.addrs + ' addresses, more than the ' + NODES + ' this diagram draws —'
    : 'More addresses than the ' + NODES + ' this diagram draws —'
}

// One pass over the capture, so it is worth doing once per file and filter and not
// on every switch into the view. It shares the capture's sharkd with the pages, and
// that answers one request at a time: on a big capture the count can hold a page up
// for a moment, which draws the placeholder rows a page in flight already draws.
let asked = ''
async function addresses() {
  if (!flowing() || !S.file) return
  const key = S.file + '\n' + S.filter
  if (asked === key) return
  asked = key
  const res = await api('addresses', { f: S.file, filter: S.filter }).catch(() => null)
  if (!res || asked !== key) return   // the filter moved on while this was out
  S.addrs = res.n
  warnFlow()
}

const lanes = []   // one lifeline element per node
let laid = ''      // the geometry the header and the lifelines were built for

function unlane() {
  for (const el of lanes) el.remove()
  lanes.length = 0
  laid = ''
}

const x = i => GUT + S.nodeW * i + (S.nodeW >> 1)

function layout() {
  const n = S.nodes.length
  const room = list.clientWidth - GUT - 12
  S.nodeW = Math.max(LANE[0], Math.min(LANE[1], n > 0 ? Math.floor(room / n) : LANE[0]))
  S.width = GUT + S.nodeW * n
  const sig = n + ':' + S.nodeW
  if (sig === laid) return   // no node came in, and the window is the size it was
  laid = sig

  unlane()
  // min, not width: a diagram narrower than the window still wants full-width rows
  // to highlight and a header band that reaches the end of it
  canvas.style.minWidth = S.width + 'px'
  const cols = $('#cols')
  cols.style.minWidth = S.width + 'px'
  cols.textContent = ''
  cols.append(span('num', 'No.'), span('ft', 'Time'))
  S.nodes.forEach((addr, i) => {
    const held = drag && drag.addr === addr   // the column being dragged right now
    const label = span('fnode' + (held ? ' grab' : ''))
    label.style.left = (x(i) - (S.nodeW >> 1)) + 'px'
    label.style.width = S.nodeW + 'px'
    label.title = addr + '\ndrag to move this column'
    label.dataset.addr = addr
    label.append(span('fname', addr))
    const off = document.createElement('button')
    off.className = 'fx'
    off.textContent = '×'
    off.title = 'Hide ' + addr + ' — adds it to the display filter'
    label.appendChild(off)
    cols.appendChild(label)

    const life = document.createElement('div')
    life.className = 'life' + (held ? ' grab' : '')
    life.style.left = x(i) + 'px'
    canvas.appendChild(life)
    lanes.push(life)
  })
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
const EDGE = 40, STEP = 14   // the band of the list a held pointer scrolls in, per frame

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
  const at = a => { const i = S.order.indexOf(a); return i < 0 ? S.order.length : i }
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
  drag.edge = e.clientX > box.right - EDGE ? 1 : e.clientX < box.left + EDGE ? -1 : 0
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
  $('#spin').hidden = false
  const term = await addrTerm(addr).catch(() => '')
  $('#spin').hidden = true
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

const SELF = 28    // px of stub for a frame addressed to where it came from

function arrow(el, row) {
  const num = el.children[0], time = el.children[1], line = el.children[2]
  const label = line.children[0], left = line.children[1], right = line.children[2]

  time.textContent = row ? cell(row, 'time') : '…'
  num.textContent = row ? row.n : ''
  line.hidden = !row
  if (!row) return

  const src = cell(row, 'src'), dst = cell(row, 'dst')
  const from = S.node.get(src), to = S.node.get(dst)
  let text = trim(cell(row, 'info'))

  if (from === undefined || to === undefined) {
    // an address past the node limit: the frame keeps its row, as a line of text
    // rather than an arrow, so a filtered set is never quietly short
    line.className = 'fa plain'
    line.style.left = GUT + 'px'
    line.style.width = Math.max(320, S.width - GUT) + 'px'
    text = [src, dst].filter(Boolean).join(' → ') + '   ' + text
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
  label.title = (proto ? proto + ': ' : '') + cell(row, 'info')
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
    if (n.s === 'Warning' || n.s === 'Note') text.classList.add('warn')
    if (n.s === 'Error') text.classList.add('err')
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
$('#field').addEventListener('click', () => {
  if ($('#field')._filter) filter($('#field')._filter)
})

// -------------------------------------------------------------------- bytes ---

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
  const data = decode((S.sources[S.src] || {}).bytes)
  const from = S.mark ? S.mark[0] : -1, to = S.mark ? S.mark[0] + S.mark[1] : -1
  const out = []
  for (let off = 0; off < data.length; off += 16) {
    let h = '', a = '', open = false
    for (let i = 0; i < 16; i++) {
      const p = off + i
      if (p >= data.length) {
        if (open) { h += '</b>'; a += '</b>'; open = false }
        h += i === 7 ? '    ' : '   '
        continue
      }
      const on = p >= from && p < to
      if (on && !open) { h += '<b>'; a += '<b>'; open = true }
      if (!on && open) { h += '</b>'; a += '</b>'; open = false }
      h += HEX[data[p]] + (i === 7 ? '  ' : ' ')
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
  $('#spin').hidden = false
  try {
    if (text) {
      const check = await api('check', { f: S.file, filter: text }).catch(err => ({ ok: false, err: err.message }))
      if (!check.ok) { $('#filter').classList.add('bad'); note(check.err); return }
    }
    $('#filter').classList.remove('bad')
    note('')
    S.filter = text
    rewind()
    await fetchPage(0)   // the slow part: sharkd builds the whole-file match bitmap here
  } finally {
    $('#spin').hidden = true
  }
}

function rewind() {
  S.pages.clear()
  S.selIdx = -1
  S.count = S.filter ? 0 : S.total
  S.end = !S.filter
  S.nodes = []          // the node columns are the pages', and those are gone
  S.node.clear()
  S.overflow = false
  S.addrs = 0           // ...and the count was of the set the filter just replaced
  warnFlow()
  unlane()
  list.scrollTop = 0
  $('#tree').textContent = ''
  hex.textContent = ''
  $('#sources').textContent = ''
  $('#field').textContent = ''
  $('#viewer').classList.remove('picked')
  counter(); sync(); paint()
  addresses()   // the filter is the answer to the warning, so re-ask on every one
}

$('#filterbar').addEventListener('submit', e => { e.preventDefault(); if (S.file) filter($('#filter').value) })
$('#flowfilter').onclick = () => $('#filter').focus()

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
  const check = await api('check', { f: S.file, filter: text }).catch(err => ({ ok: false, err: err.message }))
  if ($('#filter').value === text) $('#filter').classList.toggle('bad', !check.ok)
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

const human = n => n < 1024 ? n + ' B'
  : n < 1048576 ? (n / 1024).toFixed(0) + ' kB'
  : n < 1073741824 ? (n / 1048576).toFixed(1) + ' MB'
  : (n / 1073741824).toFixed(1) + ' GB'

async function files() {
  S.file = null
  $('#viewer').hidden = true
  $('#files').hidden = false
  for (const sel of ['#back', '#mode']) $(sel).hidden = true
  $('#brand').hidden = false
  $('#name').hidden = true
  $('#filter').placeholder = 'filter captures: name, protocol, time'
  $('#filter').value = S.find
  $('#filter').classList.remove('bad')
  closeComplete()
  sync()

  S.caps = await api('captures').catch(err => { note(err.message); return [] })
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
  filesPaint()
  $('#empty').hidden = S.filed.length > 0
  $('#empty').textContent = !S.caps.length ? 'No captures in the directory yet.'
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
    const name = span('n'), size = span('s'), at = span('t'), protos = span('p'), action = span('a')
    name.appendChild(document.createElement('a')).className = 'open'
    action.appendChild(document.createElement('a')).className = 'dl'
    action.firstChild.textContent = 'download'
    el.append(name, size, at, protos, action)
    filecanvas.appendChild(el)
    fileSlots.push(el)
  }
  return fileSlots[i]
}

function filesDraw() {
  filecanvas.style.height = (S.filed.length * CROW) + 'px'
  const first = Math.max(0, Math.floor(filelist.scrollTop / CROW) - OVER)
  const upto = Math.min(S.filed.length, first + Math.ceil(filelist.clientHeight / CROW) + OVER * 2)

  let s = 0
  for (let i = first; i < upto; i++, s++) {
    const { c, tent } = S.filed[i], el = fileSlot(s)
    el.style.top = (i * CROW) + 'px'
    el.hidden = false
    el.classList.toggle('tent', tent)

    const link = el.querySelector('a.open')
    link.textContent = c.name
    link.title = c.name
    link.dataset.name = c.name

    el.children[1].textContent = human(c.size)

    const at = el.children[2]
    at.textContent = captured(c)
    at.title = spelt(c)

    const protos = el.children[3]
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

    el.querySelector('a.dl').href = '/api/file?f=' + encodeURIComponent(c.name)
  }
  for (; s < fileSlots.length; s++) fileSlots[s].hidden = true
}

let fqueued = false
function filesPaint() {
  if (fqueued) return
  fqueued = true
  requestAnimationFrame(() => { fqueued = false; filesDraw() })
}

// One listener for the whole pool, since the rows themselves are recycled: a
// click on the name opens it, one on the download link is left to the browser.
filecanvas.addEventListener('click', e => {
  const link = e.target.closest('a.open')
  if (link) openCapture(link.dataset.name)
})
filelist.addEventListener('scroll', filesPaint, { passive: true })
new ResizeObserver(filesPaint).observe(filelist)

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
  note('opening ' + file + ' …')
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
  columns(st)

  $('#files').hidden = true
  $('#viewer').hidden = false
  $('#back').hidden = false
  $('#brand').hidden = true
  $('#name').hidden = false
  $('#name').textContent = st.filename.replace(/\.[^.]+$/, '')
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

$('#back').onclick = () => {
  const file = S.file
  files()
  if (file) api('close', { f: file }, { method: 'POST' }).catch(() => {})
}

async function upload(chosen) {
  for (const file of chosen) {
    note('uploading ' + file.name + ' …')
    try {
      const res = await fetch('/api/file?f=' + encodeURIComponent(file.name), { method: 'POST', body: file })
      const body = await res.json()
      if (body.err) throw new Error(body.err)
    } catch (err) { note(file.name + ': ' + err.message); return }
  }
  note('')
  files()
}

$('#pick').onchange = e => upload(e.target.files)
document.addEventListener('dragover', e => { e.preventDefault(); document.body.classList.add('drop') })
document.addEventListener('dragleave', () => document.body.classList.remove('drop'))
document.addEventListener('drop', e => {
  e.preventDefault()
  document.body.classList.remove('drop')
  if (e.dataTransfer.files.length) upload(e.dataTransfer.files)
})

// -------------------------------------------------------------------- theme ---

// No setting means follow the system, which is what the CSS does on its own; the
// other two states stamp data-theme and are remembered.
const THEMES = ['system', 'light', 'dark']
const MARK = { system: '◉', light: '☀', dark: '☾' }

function theme(pick) {
  if (pick === 'system') { delete document.documentElement.dataset.theme; localStorage.removeItem('theme') }
  else { document.documentElement.dataset.theme = pick; localStorage.setItem('theme', pick) }
  const button = $('#theme')
  button.textContent = MARK[pick]
  button.title = 'Theme: ' + pick + ' (click to change)'
}

$('#theme').onclick = () => {
  const now = localStorage.getItem('theme') || 'system'
  theme(THEMES[(THEMES.indexOf(now) + 1) % THEMES.length])
}
theme(localStorage.getItem('theme') || 'system')

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
  if (p.get('f')) openCapture(p.get('f'), p.get('q') || '', +p.get('n') || 0, p.get('v'))
  else files()
}

list.addEventListener('scroll', paint, { passive: true })
new ResizeObserver(paint).observe(list)

addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT') {
    if (e.key === 'Escape') { e.target.blur(); S.file ? filter('') : find('') }
    return
  }
  if (e.key === '/' || (e.key === 'f' && (e.ctrlKey || e.metaKey))) { e.preventDefault(); $('#filter').focus(); return }
  if ($('#viewer').hidden) return
  if (e.key === 'v' && !e.ctrlKey && !e.metaKey && !$('#mode').hidden) {
    view(flowing() ? 'list' : 'flow')
    return
  }
  const rows = Math.max(1, Math.floor(list.clientHeight / rowH()) - 1)
  const jump = { ArrowDown: 1, ArrowUp: -1, PageDown: rows, PageUp: -rows }[e.key]
  if (jump) { e.preventDefault(); move(jump) }
  else if (e.key === 'Home') { e.preventDefault(); reveal(0); select(0) }
  else if (e.key === 'End' && S.end) { e.preventDefault(); reveal(S.count - 1); select(S.count - 1) }
})

restore()
