# The operator, and the tcpdump its capture pods run: one image, so the cluster
# pulls one thing and a capture can be the operator's own image by default.
#
#     docker build -t ghcr.io/lyatanski/webshark-operator .

ARG ALPINE=3.22

FROM golang:alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO off and the symbol table stripped, as with webshark itself: one static
# file that runs on plain alpine. The page is embedded in it.
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /webshark-operator .

FROM alpine:${ALPINE}
# tcpdump captures and curl streams it to webshark; nsenter gets into the target
# pod's network namespace and ip says which namespace that is. busybox has the
# last two, which is why only these two are installed.
RUN apk add --no-cache tcpdump curl
COPY --from=build /webshark-operator /usr/bin/
# Runs as nobody. The capture pods do need root and four capabilities, but they
# are a different pod on a different node - see internal/controller/sniffer.go.
USER 65534:65534
EXPOSE 8080 8081
ENTRYPOINT ["webshark-operator"]
