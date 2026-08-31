# webshark - Wireshark in the browser: a static page and a Go server over
# sharkd, built here from Wireshark master with Lua enabled.
#
# Two plugins are built in here: plugins/ims.lua, which relates SIP to Diameter
# by the subscriber identity, and plugins/ims_esp, a C dissector plugin that
# recovers a capture's ESP keys from its own SIP registrations. The Lua one is
# interpreted and just gets copied; the C one is compiled against this Wireshark,
# so it goes into the source tree below before cmake sees it.
#
# Wireshark tracks master, rebuilt on a schedule by CI to pick up upstream
# changes. To pin it instead:
#
#     docker build --build-arg WIRESHARK=v4.6.7 .

ARG ALPINE=3.22

# --------------------------------------------------------------- sharkd ------
FROM alpine:${ALPINE} AS sharkd
ARG WIRESHARK=master

RUN apk add --no-cache \
        build-base cmake git bison flex python3 \
        glib-dev libgcrypt-dev libxml2-dev c-ares-dev pcre2-dev zlib-dev \
        speexdsp-dev lua5.4-dev

RUN git clone --depth=1 --branch ${WIRESHARK} \
        https://gitlab.com/wireshark/wireshark.git /src

# ENABLE_PCAP=OFF because nothing in this image captures; reading a file is
# wiretap's job, not libpcap's. ENABLE_PLUGINS=ON is for plugins/ims_esp, and
# has to be on for this build rather than the next one: it decides HAVE_PLUGINS
# in config.h, and changing that afterwards would rebuild all of libwireshark
# instead of one plugin. Optional Wireshark features are exactly what the -dev
# packages above provide - nothing else is looked for.
RUN cmake -S /src -B /build \
        -D CMAKE_BUILD_TYPE=Release \
        -D BUILD_sharkd=ON -D BUILD_tshark=OFF -D BUILD_dftest=OFF \
        -D BUILD_wireshark=OFF -D BUILD_rawshark=OFF -D BUILD_dumpcap=OFF \
        -D BUILD_capinfos=OFF -D BUILD_captype=OFF -D BUILD_editcap=ON \
        -D BUILD_mergecap=ON -D BUILD_reordercap=ON -D BUILD_text2pcap=OFF \
        -D BUILD_randpkt=OFF -D BUILD_dcerpcidl2wrs=OFF -D BUILD_mmdbresolve=OFF \
        -D BUILD_androiddump=OFF -D BUILD_sshdump=OFF -D BUILD_ciscodump=OFF \
        -D BUILD_dpauxmon=OFF -D BUILD_randpktdump=OFF -D BUILD_wifidump=OFF \
        -D BUILD_udpdump=OFF \
        -D ENABLE_LUA=ON \
        -D ENABLE_PCAP=OFF \
        -D ENABLE_PLUGINS=ON \
        -D ENABLE_WERROR=OFF \
    && cmake --build /build --parallel $(nproc)

# The ESP plugin, built into the tree above rather than out of it, because an
# epan plugin compiles against Wireshark's own private headers and only the
# source tree has them. CMakeListsCustom.txt is upstream's hook for exactly this
# (see CMakeListsCustom.txt.example) and takes a directory under /src.
#
# It is its own layer, and after the build above, so that editing the plugin
# rebuilds the plugin: cmake re-runs to pick up the new directory, and the target
# named here is the only thing ninja then has to compile. HAVE_PLUGINS is already
# what it will be, so nothing else is stale.
COPY plugins/ims_esp /src/plugins/epan/ims_esp
RUN printf 'set(CUSTOM_PLUGIN_SRC_DIR plugins/epan/ims_esp)\n' > /src/CMakeListsCustom.txt \
    && cmake -S /src -B /build \
    && cmake --build /build --parallel $(nproc) --target ims_esp \
    && DESTDIR=/out cmake --install /build --strip \
    && find /out -path '*/plugins/*' -name '*.so' ! -name 'ims_esp.so' -delete

# ------------------------------------------------------------------ api ------
FROM golang:alpine AS api
COPY src /src
# CGO off and the symbol table stripped: the result is one file that runs on
# plain alpine with nothing but sharkd next to it. The UI is embedded in it.
RUN cd /src && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /webshark

# ---------------------------------------------------------------- image ------
FROM alpine:${ALPINE}

# The runtime half of the -dev packages sharkd was built against, and nothing
# else: no node, no npm tree, nothing interpreted. libgcc is not one of them but
# libwireshark needs it for _Unwind_Resume; the node:alpine base this image used
# to sit on happened to carry it, plain alpine does not.
RUN apk add --no-cache \
        glib libgcrypt libxml2 c-ares pcre2 zlib speexdsp lua5.4-libs libgcc

COPY --from=sharkd /out/usr/local /usr/local
COPY --from=api /webshark /usr/bin/
# The Lua plugins by copy, and the ESP plugin built above by link. Binary plugins
# are looked for in a subdirectory of the plugin directory named for the Wireshark
# version, and WIRESHARK_PLUGIN_DIR below replaces the compiled-in plugin path
# rather than adding to it - so the installed one is linked in under whatever that
# version turned out to be, and /plugins stays the single directory that holds
# everything. Mounting a tree over all of /plugins hides the link with it; mount
# over /plugins/ims.lua instead.
COPY plugins/*.lua /plugins/
RUN for dir in /usr/local/lib/wireshark/plugins/*/; do \
        ln -s "$dir" "/plugins/$(basename "$dir")"; \
    done
# Wireshark's global preferences file, which is read from the data directory of
# the install above. Two things are in it: the hidden port columns the
# sequence-diagram view labels its arrows with, and the ESP preferences that let
# a protected Gm frame be read as the SIP it holds - see the comments in the file.
COPY preferences  /usr/local/share/wireshark/preferences
COPY colorfilters /usr/local/share/wireshark/colorfilters

ENV WIRESHARK_PLUGIN_DIR=/plugins \
    CAPTURES=/captures \
    LISTEN=:8085 \
    SHARKD_SESSIONS=4 \
    SHARKD_IDLE=600 \
    SCAN_FRAMES=20000

RUN mkdir -p /captures
VOLUME /captures
EXPOSE 8085
# Root on purpose: the captures directory is a bind mount owned by whoever runs
# the capture - ptcpdump writes it as root - and uploads have to land in it.
ENTRYPOINT ["webshark"]
