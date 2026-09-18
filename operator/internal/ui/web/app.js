// The operator's page. Everything here goes through the operator's API, which
// goes through the Kubernetes API: ticking pods and pressing Capture creates a
// PacketCapture object, the same one `kubectl apply` would, and the table below
// is that object's status read back.

const S = {
  ns: localStorage.getItem('ns') ?? '',
  selector: '',
  webshark: localStorage.getItem('webshark') ?? '',
  picked: new Set(),          // "namespace/pod" of the ticked rows
  folds: new Map(),           // "namespace/capture" -> opened or closed, once said
  pods: [],
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

async function refresh() {
  const query = new URLSearchParams({ namespace: S.ns, selector: S.selector })
  const [pods, captures, websharks] = await Promise.all([
    api('pods?' + query), api('captures'), api('websharks'),
  ])
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
  $('go').disabled = !S.websharks.length

  const chosen = current()
  const open = $('open')
  open.hidden = !chosen
  if (chosen) {
    open.href = browseURL(chosen)
    open.title = 'opens in this page - ' + (chosen.url || chosen.serviceURL || '')
    open.onclick = inFrame(chosen.namespace + '/' + chosen.name)
  }
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

function paintPods() {
  const rows = S.pods.map(pod => {
    const key = pod.namespace + '/' + pod.name
    const running = pod.phase === 'Running'
    if (!running) S.picked.delete(key)

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
        S.ns ? pod.name : pod.namespace + '/' + pod.name),
      el('td', {}, pod.phase),
      el('td', { className: 'node' }, pod.node ?? ''),
      el('td', {}, captures.length ? captures : ''))
  })
  $('podlist').replaceChildren(...rows)
  $('all').checked = false
  count()
}

const labelText = labels => Object.entries(labels ?? {}).map(([k, v]) => k + '=' + v).join('\n')

function count() {
  const picked = S.picked.size
  const running = S.pods.filter(p => p.phase === 'Running').length
  $('podcount').textContent = picked ? picked + ' of ' + running + ' selected' : running + ' running'
  $('go').textContent = picked ? 'Capture ' + picked + ' pod' + (picked > 1 ? 's' : '')
    : S.selector ? 'Capture what matches' : 'Capture everything here'
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
    const body = el('div', { className: 'body' },
      targets.length ? el('table', {},
        el('thead', {}, el('tr', {},
          el('th', { textContent: 'pod' }), el('th', { textContent: 'state' }),
          el('th', { textContent: 'capture file' }), el('th', { textContent: 'since' }))),
        el('tbody', {}, ...targets.map(t => el('tr', {},
          el('td', { className: 'pod', title: t.capturer ? 'captured by ' + t.capturer : '' },
            t.namespace + '/' + t.pod),
          el('td', {}, el('span', { className: 'badge ' + t.phase, textContent: t.phase })),
          // the file is linked from the moment tcpdump starts: the upload is
          // streamed, so webshark can open it while it is still growing
          el('td', { className: 'file' }, t.file
            ? el('a', { href: base + '#f=' + encodeURIComponent(t.file), textContent: t.file, onclick: inFrame(t.file) })
            : ''),
          // why it failed matters more than when it started, so the last column
          // is whichever of the two there is
          el('td', { className: t.message ? 'msg' : 'node' }, t.message || ago(t.startedAt))))))
        : el('p', { className: 'quiet', textContent: message(status) }))

    const details = el('details', { className: 'capture', open },
      el('summary', {},
        el('span', { className: 'name', textContent: capture.metadata.name }),
        el('span', { className: 'quiet', textContent: capture.metadata.namespace }),
        el('span', { className: 'what', textContent: what(spec) }),
        el('span', { className: 'spacer' }),
        ...counts(status),
        pause, remove),
      body)
    details.addEventListener('toggle', () => S.folds.set(key, details.open))
    return details
  }))
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
  const picked = [...S.picked]
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
    podSelector: S.selector,
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
$('selector').addEventListener('input', e => {
  S.selector = e.target.value.trim()
  clearTimeout(typing)
  typing = setTimeout(tick, 300)
})

$('all').addEventListener('change', e => {
  for (const pod of S.pods) {
    if (pod.phase !== 'Running') continue
    const key = pod.namespace + '/' + pod.name
    e.target.checked ? S.picked.add(key) : S.picked.delete(key)
  }
  paintPods()
  $('all').checked = e.target.checked
})

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
