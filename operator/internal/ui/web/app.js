// The operator's page. Everything here goes through the operator's API, which
// goes through the Kubernetes API: ticking pods and pressing Capture creates a
// PacketCapture object, the same one `kubectl apply` would, and the table below
// is that object's status read back.

const S = {
  ns: localStorage.getItem('ns') ?? '',
  query: '',                  // what is in the search box
  webshark: localStorage.getItem('webshark') ?? '',
  picked: new Set(),          // "namespace/pod" of the ticked rows
  folds: new Map(),           // "namespace/capture" -> opened or closed, once said
  pods: [],
  shown: [],                  // the pods the query leaves, best match first
  captures: [],
  websharks: [],
}

const $ = id => document.getElementById(id)
const el = (tag, props, ...kids) => {
  const node = Object.assign(document.createElement(tag), props)
  for (const kid of kids.flat()) if (kid != null) node.append(kid)
  return node
}

async function api(path, init) {
  const res = await fetch('/api/' + path, init)
  const body = res.status === 204 ? null : await res.json().catch(() => null)
  if (!res.ok) throw new Error(body?.err || res.statusText)
  return body
}

let toasting
function toast(message, bad) {
  const box = $('toast')
  box.textContent = message
  box.classList.toggle('err', !!bad)
  box.hidden = false
  clearTimeout(toasting)
  toasting = setTimeout(() => { box.hidden = true }, bad ? 8000 : 3000)
}

// ------------------------------------------------------------------ loading

async function namespaces() {
  const list = await api('namespaces')
  const select = $('namespace')
  select.replaceChildren(
    el('option', { value: '', textContent: 'all namespaces' }),
    ...list.map(ns => el('option', { value: ns, textContent: ns })))
  if (!list.includes(S.ns)) S.ns = ''
  select.value = S.ns
}

// The selector the pod list in hand was asked for with. A search is matched in
// the page, so it is only a change of selector that has to go back to the API
// server - typing in the box otherwise re-lists nothing.
let listed = ''

async function refresh() {
  const asked = selector()
  const query = new URLSearchParams({ namespace: S.ns, selector: asked })
  const [pods, captures, websharks] = await Promise.all([
    api('pods?' + query), api('captures'), api('websharks'),
  ])
  listed = asked
  S.pods = pods
  S.captures = captures
  S.websharks = websharks
  paintWebsharks()
  paintPods()
  paintCaptures()
}

// A refresh that says so rather than failing silently, for the polling loop -
// which keeps going: an operator being restarted is a blip, not an error.
async function tick() {
  try { await refresh() } catch (e) { console.warn(e) }
}

// ----------------------------------------------------------------- webshark

function paintWebsharks() {
  const select = $('webshark')
  const keys = S.websharks.map(w => w.namespace + '/' + w.name)
  if (!keys.includes(S.webshark)) S.webshark = keys[0] ?? ''
  select.replaceChildren(...S.websharks.map(w => el('option', {
    value: w.namespace + '/' + w.name,
    textContent: w.namespace + '/' + w.name + (w.ready ? '' : ' (not ready)'),
  })))
  if (!S.websharks.length) {
    select.replaceChildren(el('option', { textContent: 'no Webshark in the cluster' }))
  }
  select.value = S.webshark

  const chosen = current()
  const open = $('open')
  open.hidden = !chosen
  if (chosen) {
    open.href = browseURL(chosen)
    open.title = 'opens in this page - ' + (chosen.url || chosen.serviceURL || '')
    open.onclick = inFrame(chosen.namespace + '/' + chosen.name)
  }
  count()
}

const current = () => S.websharks.find(w => w.namespace + '/' + w.name === S.webshark)

// The address to open a Webshark at: the path the operator serves it under
// itself. It is a path and not a URL on purpose - whatever reached this page,
// port-forward or NodePort or ingress, reaches webshark through it, and no
// address webshark knows of its own would: its service is a cluster address the
// browser cannot follow, and its port is not the port this page was reached on.
const browseURL = w => w?.path ?? ''

// The address the capture files are linked at: the Webshark they were uploaded
// to, or the raw URL the capture names if that is somewhere else entirely -
// which is only reachable if it is an ingress.
function websharkURL(capture) {
  const match = S.websharks.find(w => w.serviceURL === capture.status?.websharkURL)
  if (match) return browseURL(match)
  const raw = capture.status?.websharkURL || ''
  return raw && !raw.endsWith('/') ? raw + '/' : raw
}

// --------------------------------------------------------------------- frame
//
// webshark in the page, rather than in a window of its own with an address to
// get wrong. It is served under this origin (internal/ui/proxy.go), so the
// frame is same-origin and the theme, being localStorage, is the same one.

// Anchors keep their href - so ctrl-click, middle-click and "open in new tab"
// all still do what they say - and a plain left click opens the frame instead.
const inFrame = label => e => {
  if (e.button || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
  e.preventDefault()
  view(e.currentTarget.href, label)
}

function view(url, label) {
  const frame = $('frame')
  // Where the frame is now, which is not what it was last given: webshark
  // changes the hash as it is clicked around in. Reading it needs the frame to
  // be same-origin, which it is unless a capture named a webshark somewhere
  // else entirely. Reopening what is already there leaves it as it was left,
  // dissected file and all.
  let at
  try { at = frame.contentWindow.location.href } catch { at = frame.src }
  if (at !== url) frame.src = url
  $('viewing').textContent = label
  $('pop').href = url
  $('viewer').hidden = false
}

const unview = () => { $('viewer').hidden = true }

// --------------------------------------------------------------------- pods
//
// The box above the list is a search, and it is matched here rather than by the
// API server: a pod stays when every word typed is somewhere in its name or in
// one of its labels, the letters in order and gaps allowed - so "pcs0" finds
// sip-pcscf-0, and "core" finds it by tier=core. The list is already in the
// page, so this costs nothing and narrows as it is typed.
//
// Typing what only a label selector has - = ! < > ( in notin - means one
// instead, and it goes to the API server as it always did. That is not just for
// exactness: a selector is the one thing an unticked Capture can be left to
// follow as pods come and go, and a search is not.
const isSelector = q => /[=!<>(]|\s(in|notin)\s/.test(q)
const selector = () => isSelector(S.query) ? S.query : ''

const podKey = pod => pod.namespace + '/' + pod.name
const isRunning = pod => pod.phase === 'Running'

// The pod as its row shows it, which is also what the search reads: with one
// namespace chosen, every row's namespace is the same and matching it would
// only let "kube" find everything in kube-system.
const podName = pod => S.ns ? pod.name : pod.namespace + '/' + pod.name

// One word against one string: every letter of the word, in order. Tried from
// every place its first letter appears, because the first of them is not always
// the one that leads the best match - the "pcs" of sip-pcscf-0 is in pcscf, not
// the p of sip, and taking the first would both score it low and mark the wrong
// letters.
function fuzzy(word, text) {
  const letters = [...word]
  let best = null
  for (let at = text.indexOf(letters[0]); at >= 0; at = text.indexOf(letters[0], at + 1)) {
    const m = align(letters, text, at)
    if (m && (best === null || m.score > best.score)) best = m
  }
  return best
}

// The word from one starting place, every letter after it taken where it first
// can be. Letters found together score, reaching over others costs, and one
// starting a word - after a dash, a dot, the = of a label - is worth something:
// so a tight match near the front beats the same letters scattered. Answers
// with where they were, for the row to mark.
function align(letters, text, start) {
  let score = 0, from = 0, run = 0
  const hits = []
  for (let i = 0; i < letters.length; i++) {
    const at = i ? text.indexOf(letters[i], from) : start
    if (at < 0) return null
    run = at === from && from > 0 ? run + 1 : 0
    score += 10 + 6 * run - Math.min(at - from, 12)
    if (at === 0 || '-_./=:'.includes(text[at - 1])) score += 8
    hits.push(at)
    from = at + 1
  }
  return { score, hits }
}

// The pods a search leaves, best match first. Every word has to match, but each
// may match somewhere else: "pcscf core" is a name and a label.
function search(pods) {
  const words = S.query.toLowerCase().split(/\s+/).filter(Boolean)
  if (!words.length || isSelector(S.query)) return pods.map(pod => ({ pod, hits: [] }))

  const found = []
  for (const pod of pods) {
    const name = podName(pod).toLowerCase()
    const labels = Object.entries(pod.labels ?? {}).map(([k, v]) => k + '=' + v)
    let score = 0, hits = [], via = null, every = true
    for (const word of words) {
      // A label match counts, but not as much as the same match in the name,
      // which is what the reader is looking at. The label that did it is kept
      // with it, since a row matched by a label it does not show says nothing.
      const inName = fuzzy(word, name)
      let best = inName && { score: 2 * inName.score, hits: inName.hits, via: null }
      for (const label of labels) {
        const m = fuzzy(word, label.toLowerCase())
        if (m && (best === null || m.score > best.score)) {
          best = { score: m.score, hits: [], via: { label, hits: m.hits } }
        }
      }
      if (!best) { every = false; break }
      score += best.score
      hits = hits.concat(best.hits)
      via ??= best.via
    }
    if (every) found.push({ pod, score, hits, via })
  }
  // A stopped pod can still be the one being looked for - it is shown, and
  // dimmed - but it cannot be captured, so it is never what a search leads with.
  return found.sort((a, b) => isRunning(b.pod) - isRunning(a.pod)
    || b.score - a.score
    || podName(a.pod).localeCompare(podName(b.pod)))
}

// the letters that matched, marked, so a row says why it is there
function mark(text, hits) {
  if (!hits.length) return [text]
  const on = new Set(hits)
  const out = []
  let run = '', lit = on.has(0)
  for (let i = 0; i < text.length; i++) {
    if (on.has(i) !== lit) {
      out.push(lit ? el('mark', { textContent: run }) : run)
      run = ''
      lit = on.has(i)
    }
    run += text[i]
  }
  out.push(lit ? el('mark', { textContent: run }) : run)
  return out
}

function paintPods() {
  // a pod that has stopped running cannot be captured, whether the search left
  // it in view or not
  for (const pod of S.pods) if (!isRunning(pod)) S.picked.delete(podKey(pod))

  S.shown = search(S.pods)
  const rows = S.shown.map(({ pod, hits, via }) => {
    const key = podKey(pod)
    const running = isRunning(pod)

    const tick = el('input', { type: 'checkbox', checked: S.picked.has(key), disabled: !running })
    tick.addEventListener('change', () => {
      tick.checked ? S.picked.add(key) : S.picked.delete(key)
      count()
    })

    const captures = (pod.captures ?? []).map(c =>
      el('span', { className: 'badge ' + c.phase, textContent: c.capture, title: c.phase }))

    return el('tr', { className: running ? '' : 'off' },
      el('td', { className: 'tick' }, tick),
      el('td', { className: 'pod', title: labelText(pod.labels) },
        mark(podName(pod), hits),
        via ? el('span', { className: 'via' }, mark(via.label, via.hits)) : null),
      el('td', {}, pod.phase),
      el('td', { className: 'node' }, pod.node ?? ''),
      el('td', {}, captures.length ? captures : ''))
  })
  if (!rows.length && S.pods.length) {
    rows.push(el('tr', {}, el('td', { className: 'quiet', colSpan: 5, textContent: 'nothing here matches' })))
  }
  $('podlist').replaceChildren(...rows)
  $('all').checked = false
  count()
}

const labelText = labels => Object.entries(labels ?? {}).map(([k, v]) => k + '=' + v).join('\n')

// The pods an unticked Capture takes: the ones the search left. An empty box,
// or a selector, leaves none by name - the capture is then the selector's or
// the whole namespace's, and goes on matching pods that turn up later.
const matched = () => !S.query || isSelector(S.query) ? []
  : S.shown.filter(({ pod }) => isRunning(pod)).map(({ pod }) => podKey(pod))

function count() {
  const picked = S.picked.size
  const running = S.pods.filter(isRunning).length
  const hits = matched().length
  const searching = !!S.query && !isSelector(S.query)
  $('podcount').textContent = picked ? picked + ' of ' + running + ' selected'
    : searching ? hits + ' of ' + running + ' matched'
      : running + ' running'

  // ticked pods first: a search is how they were found, not what is captured
  const take = picked || hits
  $('go').textContent = take ? 'Capture ' + take + ' pod' + (take > 1 ? 's' : '')
    : isSelector(S.query) ? 'Capture what matches'
      : searching ? 'Capture' : 'Capture everything here'
  $('go').disabled = !S.websharks.length || (searching && !take)
}

// ----------------------------------------------------------------- captures

function paintCaptures() {
  if (!S.captures.length) {
    $('capturelist').replaceChildren(el('p', { className: 'quiet', textContent: 'nothing captured yet' }))
    return
  }
  // a capture that has gone takes its fold with it
  const live = new Set(S.captures.map(c => c.metadata.namespace + '/' + c.metadata.name))
  for (const key of S.folds.keys()) if (!live.has(key)) S.folds.delete(key)

  $('capturelist').replaceChildren(...S.captures.map(capture => {
    const spec = capture.spec ?? {}, status = capture.status ?? {}
    const targets = status.targets ?? []
    const key = capture.metadata.namespace + '/' + capture.metadata.name
    // A capture opens itself while it is running, and after that it is the
    // reader's to open and close. Their answer has to be kept: this list is
    // rebuilt on every poll, and a capture that decided for itself each time
    // would fold back up a few seconds after it finished - which is the moment
    // its file is worth clicking, and it is behind the fold.
    const open = S.folds.get(key) ?? targets.some(t => t.phase === 'Capturing')

    const pause = el('button', { className: 'link', textContent: spec.paused ? 'resume' : 'pause' })
    pause.addEventListener('click', async e => {
      e.preventDefault()
      await act('pause?' + new URLSearchParams({
        namespace: capture.metadata.namespace, name: capture.metadata.name, paused: String(!spec.paused),
      }), 'POST')
    })

    const remove = el('button', { className: 'link', textContent: 'delete' })
    remove.addEventListener('click', async e => {
      e.preventDefault()
      await act('captures?' + new URLSearchParams({
        namespace: capture.metadata.namespace, name: capture.metadata.name,
      }), 'DELETE')
    })

    const base = websharkURL(capture)
    // Every card shows the same four columns, and they are named so the
    // stylesheet can give them the same widths in all of them: one capture's
    // pods then read down the page against the next one's, not against a
    // column that moved because a file name was longer.
    const body = el('div', { className: 'body' },
      targets.length ? el('table', {},
        el('thead', {}, el('tr', {},
          el('th', { className: 'pod', textContent: 'pod' }),
          el('th', { className: 'state', textContent: 'state' }),
          el('th', { className: 'file', textContent: 'capture file' }),
          el('th', { className: 'since', textContent: 'since' }))),
        el('tbody', {}, ...targets.flatMap(t => {
          // Why a capture stopped is a word or two - paused, pod gone - and it
          // says more than when it started, so it takes the last column. What a
          // pod that never captured leaves behind is a paragraph of kubelet or
          // tcpdump instead, and that gets a line of its own under the row: a
          // column narrow enough to line up with the other cards is not
          // somewhere a sentence can be read.
          const brief = t.phase === 'Completed' || t.phase === 'Capturing'
          const row = el('tr', {},
            el('td', { className: 'pod', title: t.capturer ? 'captured by ' + t.capturer : '' },
              t.namespace + '/' + t.pod),
            el('td', { className: 'state' },
              el('span', { className: 'badge ' + t.phase, textContent: t.phase })),
            // the file is linked from the moment tcpdump starts: the upload is
            // streamed, so webshark can open it while it is still growing
            el('td', { className: 'file' }, t.file
              ? el('a', { href: base + '#f=' + encodeURIComponent(t.file), textContent: t.file, onclick: inFrame(t.file) })
              : ''),
            el('td', { className: brief && t.message ? 'since msg' : 'since' },
              brief && t.message ? t.message : ago(t.startedAt)))
          if (brief || !t.message) return [row]
          return [row, el('tr', { className: 'why' },
            el('td', { className: 'msg', colSpan: 4, textContent: t.message }))]
        })))
        : el('p', { className: 'quiet', textContent: message(status) }))

    const details = el('details', { className: 'capture', open },
      el('summary', {},
        el('span', { className: 'head' },
          el('span', { className: 'name', textContent: capture.metadata.name }),
          el('span', { className: 'quiet', textContent: capture.metadata.namespace })),
        el('span', { className: 'what', textContent: what(spec) }),
        el('span', { className: 'acts' }, ...counts(status), pause, remove)),
      body)
    details.addEventListener('toggle', () => S.folds.set(key, details.open))
    return details
  }))
  fit()
}

// What a capture was asked for is the one thing in its heading with no length
// to speak of - a filter can be a line by itself. So it is laid beside the name
// while it fits there and dropped onto a line of its own when it stops
// fitting; the state and the buttons keep the first line either way. Whether it
// fits is a question about the drawn page, so it is asked of it: the heading is
// laid out unwrapped first, and stacked only where that spills.
function fit() {
  for (const summary of document.querySelectorAll('.capture > summary')) {
    const what = summary.querySelector('.what')
    summary.classList.remove('stack')
    if (what.scrollWidth > what.clientWidth + 1) summary.classList.add('stack')
  }
}

// what the capture was asked for, in the form it was asked in
function what(spec) {
  const bits = []
  if (spec.podSelector?.matchLabels) bits.push(labelText(spec.podSelector.matchLabels).replaceAll('\n', ','))
  if (spec.podNames?.length) bits.push(spec.podNames.length + ' pod' + (spec.podNames.length > 1 ? 's' : ''))
  bits.push(spec.filter || 'all traffic')
  bits.push(spec.duration || '5m')
  return bits.join(' · ')
}

const counts = status => [
  ['Capturing', status.capturing], ['Completed', status.completed], ['Failed', status.failed],
].filter(([, n]) => n).map(([phase, n]) =>
  el('span', { className: 'badge ' + phase, textContent: n + ' ' + phase.toLowerCase() }))

// when there are no targets, the Ready condition is the reason why
const message = status =>
  (status.conditions ?? []).find(c => c.type === 'Ready')?.message ?? 'no pods yet'

function ago(when) {
  if (!when) return ''
  const secs = Math.max(0, (Date.now() - Date.parse(when)) / 1000)
  if (secs < 90) return Math.round(secs) + 's'
  if (secs < 5400) return Math.round(secs / 60) + 'm'
  return Math.round(secs / 3600) + 'h'
}

async function act(path, method) {
  try {
    await api(path, { method })
    await refresh()
  } catch (e) { toast(e.message, true) }
}

// -------------------------------------------------------------------- start

$('start').addEventListener('submit', async e => {
  e.preventDefault()
  const picked = S.picked.size ? [...S.picked] : matched()
  const spaces = new Set(picked.map(key => key.split('/')[0]))
  const chosen = current()

  // The PacketCapture is an object and has to live in a namespace. One
  // namespace's worth of pods puts it there; pods from several, or a selector
  // over the whole cluster, puts it next to the webshark it feeds and widens
  // its namespaceSelector to match.
  let namespace = S.ns, namespaceSelector
  if (spaces.size === 1) namespace = [...spaces][0]
  else if (spaces.size > 1 || !S.ns) {
    namespace = chosen?.namespace ?? [...spaces][0]
    namespaceSelector = ''
  }
  if (!namespace) return toast('pick a namespace, or a pod', true)

  const body = {
    namespace,
    // The name is the object's, and the one the capture files are led by - so an
    // empty box is a generated name in both places, and not a file that says
    // nothing about where it came from.
    name: $('capname').value.trim(),
    namespaceSelector,
    podNames: picked.map(key => key.split('/')[1]),
    podSelector: selector(),
    filter: $('filter').value.trim(),
    interface: $('iface').value.trim() || 'any',
    duration: $('duration').value.trim() || '5m',
    snaplen: +$('snaplen').value || 0,
    maxTargets: Math.max(10, picked.length),
    webshark: S.webshark,
  }

  try {
    const made = await api('captures', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    S.picked.clear()
    $('capname').value = ''
    toast('started ' + made.metadata.name)
    await refresh()
  } catch (err) { toast(err.message, true) }
})

// ------------------------------------------------------------------- events

$('namespace').addEventListener('change', e => {
  S.ns = e.target.value
  localStorage.setItem('ns', S.ns)
  S.picked.clear()
  tick()
})

$('webshark').addEventListener('change', e => {
  S.webshark = e.target.value
  localStorage.setItem('webshark', S.webshark)
  paintWebsharks()
})

let typing
$('search').addEventListener('input', e => {
  S.query = e.target.value.trim()
  $('mode').hidden = !isSelector(S.query)
  paintPods()                     // the search is matched here, so it is instant
  if (selector() !== listed) {    // a selector is the API server's to apply
    clearTimeout(typing)
    typing = setTimeout(tick, 300)
  }
})

$('all').addEventListener('change', e => {
  for (const { pod } of S.shown) {
    if (pod.phase !== 'Running') continue
    e.target.checked ? S.picked.add(podKey(pod)) : S.picked.delete(podKey(pod))
  }
  paintPods()
  $('all').checked = e.target.checked
})

// the headings are measured, so a narrower window has to measure them again
addEventListener('resize', fit)

$('close').addEventListener('click', unview)
addEventListener('keydown', e => {
  // only when the page itself has the focus - a keystroke inside the frame is
  // webshark's, and it has its own use for Escape
  if (e.key === 'Escape' && !$('viewer').hidden) unview()
})

$('theme').addEventListener('click', () => {
  const dark = matchMedia('(prefers-color-scheme: dark)').matches
  const now = document.documentElement.dataset.theme || (dark ? 'dark' : 'light')
  const next = now === 'dark' ? 'light' : 'dark'
  document.documentElement.dataset.theme = next
  localStorage.setItem('theme', next)
})

namespaces().then(tick).catch(e => toast(e.message, true))
// A capture is minutes long, and the operator itself only re-reads pod status
// every few seconds, so there is nothing here that a slower poll would miss.
setInterval(tick, 4000)
