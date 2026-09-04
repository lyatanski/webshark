# webshark

Wireshark in the browser. A static page and a small Go server over
[`sharkd`](https://www.wireshark.org/docs/man-pages/sharkd.html), which does all
the dissecting — point it at a directory of captures and read them from a
browser, with no client to install.

- **Packet list** — paged and virtualised, so a 600 MB capture opens as fast as a
  small one; Wireshark's own columns and coloring rules.
- **Flow view** — Wireshark's flow graph: a lane per address, an arrow per frame,
  lanes draggable into the order you want to read them in.
- **Dissection tree and bytes** — the full protocol tree, hex with the selected
  field highlighted, one tab per data source.
- **Display filters** — compiled by sharkd as you type, with field-name
  completion.
- **Captures list** — sizes, capture times and a protocol summary per file;
  upload by drag-and-drop, download, close.
- **IMS extras** — a Lua plugin relating SIP, Diameter and the RTP they set up
  by subscriber identity, and a C plugin recovering ESP SAs from a capture's own
  AKA registration, so protected Gm traffic dissects with nothing configured.

## Run

```sh
docker run --rm -p 8085:8085 -v /path/to/captures:/captures \
    ghcr.io/lyatanski/webshark
```

Then open <http://localhost:8085>. Captures are whatever files are in the
mounted directory — nothing is copied and nothing is written except uploads.

Configuration is environment variables, all with the defaults shown:

| | |
|---|---|
| `CAPTURES=/captures` | directory served |
| `LISTEN=:8085` | listen address |
| `SHARKD_SESSIONS=4` | captures kept loaded at once |
| `SHARKD_IDLE=600` | seconds before an idle capture is unloaded |
| `SCAN_FRAMES=20000` | frames dissected for the protocol summary |
| `WEB=` | serve the UI off disk instead of the embedded copy |

## Build

`docker build .` builds sharkd from Wireshark master with Lua and plugins
enabled, `plugins/ims_esp` against it, and the server around both;
`--build-arg WIRESHARK=v4.6.7` pins a release instead. CI rebuilds and pushes
the image on every push.

The plugin is built in its own layer after Wireshark, so editing it costs one
compile and a link rather than another hour.

## Layout

```
src/main.go      HTTP handlers and the JSON API (documented at the top of the file)
src/sharkd.go    one sharkd per open capture, and the pool that ends them
src/capture.go   capture times from the file header, cached protocol scans
src/web/         the UI - no framework, no build step: app.js is what the browser runs
plugins/ims.lua  SIP ↔ Diameter ↔ RTP correlation by subscriber identity
plugins/ims_esp/ ESP SAs from a capture's own SIP registration, in C: a
                 postdissector that installs them as the file is read, so sharkd,
                 tshark and Wireshark alike need telling nothing
preferences      hidden port columns the flow view labels arrows with, plus ESP settings
colorfilters     coloring rules
```

## Working on the UI

Mount the working tree over the embedded copy — no rebuild needed for
JS/CSS/HTML:

```sh
docker run --rm -p 8085:8085 -v /path/to/captures:/captures \
    -e WEB=/web -v "$PWD/src/web:/web:ro" ghcr.io/lyatanski/webshark
```
