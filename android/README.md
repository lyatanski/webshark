# webshark for Android

The same server and the same sharkd, in a WebView. Nothing in `src/` knows about
Android: `app.js` asks for relative paths, so a WebView on `127.0.0.1:8085` is
the whole of the port, and the server takes the path to sharkd from `$SHARKD` as
it always has.

## Build

```sh
cd ..
docker build -f Dockerfile.android --target apk --output type=local,dest=out .
```

writes `out/webshark-arm64.apk`, and is the whole build: the two toolchains this
needs - the NDK for arm64, a JDK and the Android SDK for the APK - are both in
`Dockerfile.android`, so nothing has to be installed to produce an APK.

```sh
adb install -r out/webshark-arm64.apk
```

To work on the app itself, stop at `--target tree`, which is the cross-compile
alone and writes its result into this project for Android Studio or a local
Gradle to build around:

```sh
cd ..
docker build -f Dockerfile.android --target tree \
    --output type=local,dest=android/app/src/main .
```

which produces

```
app/src/main/jniLibs/arm64-v8a/libsharkd.so    sharkd, statically linked
app/src/main/jniLibs/arm64-v8a/libwebshark.so  the Go server, with the UI in it
app/src/main/assets/share/                     } what the image has in
app/src/main/assets/share/preferences          } /usr/local/share/wireshark:
app/src/main/assets/share/colorfilters         } Wireshark's data files, and
                                               } webshark's two over them
app/src/main/assets/plugins/ims.lua            the SIP-to-Diameter plugin
```

`assets/share` is 4 MB and most of it is dictionaries - Diameter, RADIUS, the
DTDs the XML dissector reads. They are not optional decoration: a field that
comes out of one of them does not exist without it, `Field.new` raises on a field
that does not exist, and one such call aborts the whole of `ims.lua` - which is
what shipping only `preferences` and `colorfilters` here used to do.

Then

```sh
cd android
gradle assembleDebug        # or open this directory in Android Studio
adb install app/build/outputs/apk/debug/app-debug.apk
```

There is no Gradle wrapper checked in; `gradle wrapper` will write one if you
want it.

Neither of those `.so` files is a library. Android will not execute a file out of
an app's writable data directory - since API 29 the only place an app may execute
from is where its native libraries are unpacked, and only files named `lib*.so`
are unpacked there at all. So they are executables carrying a library's name,
which is also why `app/build.gradle.kts` sets `useLegacyPackaging = true`: that
is `android:extractNativeLibs="true"`, and without it nothing is unpacked and
nothing runs.

## Releases

`.github/workflows/android.yml` runs the same `--target apk` build and attaches
the APK to a GitHub release:

```sh
git tag v0.1 && git push origin v0.1
```

Not on every push, as the container image is - the cross-compile is an hour of
runner time. A manual run from the Actions tab builds the same APK and leaves it
as an artifact on the run instead of publishing it.

## What the shell does

`Server.kt` starts `libwebshark.so` as a child process, with every path it would
otherwise find under `/usr` named in its environment:

| | |
|---|---|
| `SHARKD` | `libsharkd.so`, next to the server in the native library directory |
| `CAPTURES` | `Android/data/net.webshark/files/captures` |
| `LISTEN` | `127.0.0.1:8085` - loopback, so nothing else on the device can read the captures |
| `WIRESHARK_DATA_DIR` | where Wireshark's data files, `preferences` and `colorfilters` were unpacked |
| `WIRESHARK_PLUGIN_DIR` | where `ims.lua` was unpacked |
| `WIRESHARK_CONFIG_DIR`, `HOME` | a writable configuration directory, there being no passwd entry to derive one from |

`ServerService.kt` is a service holding that process, so a short trip out of the
app does not unload the capture - a plain service and not a foreground one, the
notification a foreground service costs being worth more than surviving out of
sight indefinitely. `MainActivity.kt` is the WebView, and waits for the port to
answer before loading rather than for a fixed time.

`SHARKD_SESSIONS` is 1 and `SCAN_FRAMES` is 2000, against the 4 and 20000 the
container uses. sharkd holds a whole dissected capture in memory and the
low-memory killer does not care that it is a child process; a capture the desktop
build opens without noticing is not one a phone will survive.

## Getting a capture in

The web UI takes an upload by drag-and-drop, and a phone has no such gesture. So
the app is a handler for captures instead: open or share one from a file manager,
a mail client or a download, and it is copied into the captures directory and
opened. `adb push <file> /sdcard/Android/data/net.webshark/files/captures/`
works too, and needs no intent at all.

Being *offered* for a capture is the awkward part, because Android has no MIME
type for one. What arrives in the intent is whatever the app handing the file
over happens to believe, so `AndroidManifest.xml` matches four ways:

| | |
|---|---|
| by type | the IANA `application/vnd.tcpdump.pcap` and the conventional spellings around it - `application/x-pcapng`, `application/pcap`, `application/cap` and the rest |
| by name | `.pcap`, `.pcapng`, `.cap`, `.ntar` and their `.gz` forms, for the file manager that guesses a type from the extension and guesses something else |
| by neither | `application/octet-stream`, which is what a download or a mail attachment is |
| by sharing | the same types again for `SEND`, which carries no name to match on |

The third of those is the blunt one: it is why webshark appears under "Open with"
for any unnamed binary on the device, and also the only reason a capture out of
Gmail or the Downloads provider can be opened at all. Dropping that filter is a
line, if the noise is worse than the loss.

The name filter is longer than it looks like it should be. `android:pathPattern`
is not a regular expression - its `.*` never backtracks, so `.*\.pcap` stops at
the first dot in the path and misses `my.capture.pcap` - so each suffix is
repeated per dot it may have to step over. The path is also only consulted when
the filter names a host, which is why that one is `content` only.

What is opened is opened, not just imported: the file is copied in, and the
WebView is pointed at `#f=<name>`, which is the fragment the UI already keeps its
state in. A capture arriving at a running app takes the same route -
`hashchange` in `app.js` reopens on it - so sharing a second capture into an open
one switches to it rather than reloading the list.

A native "import" button in the shell is the obvious next thing, but it needs
chrome above a UI that already has its own header, so it is left out until the
intent route proves not to be enough.

## Size

`libsharkd.so` is around 133 MB: Wireshark's dissectors are most of it and they
are statically linked, so it is what a whole dissection engine weighs. Building
it `-Os` instead of the release default is worth 1 MB of that and costs
dissection speed, which on a phone is the wrong trade. The APK compresses it -
`useLegacyPackaging = true` stores native libraries compressed and unpacks them
at install - so what is downloaded is well under half of that and what lands on
disk is all of it.

## Not done yet

- **arm64 only.** `abiFilters` and `Dockerfile.android` both name `arm64-v8a`;
  another ABI is a second pass over the same file with `ANDROID_ABI` and the NDK
  triple changed.
- **No signing config**, so this is a debug build, signed with a key Gradle
  generates in whichever container built it. It installs, but one build's APK
  will not install *over* another's - `adb uninstall net.webshark` first.
  A real signing config is a keystore and four lines in `app/build.gradle.kts`,
  with the keystore reaching CI as a secret.
- **`editcap`/`mergecap`** are off in `Dockerfile.android` as they are in the
  main image today; turning them on is two more binaries to name `lib*.so`.
