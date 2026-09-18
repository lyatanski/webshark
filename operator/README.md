# webshark-operator

tcpdump in any pod in the cluster, streaming into webshark as it runs - without
touching the pod being captured. Two objects: a `PacketCapture` says which pods,
and a `Webshark` is the deployment the captures land in - the operator keeps
both.

```sh
helm install ws charts/webshark-operator -n webshark --create-namespace
kubectl label ns webshark pod-security.kubernetes.io/enforce=privileged
kubectl apply -f operator/examples/packetcapture.yaml
```

```console
$ kubectl -n ims get packetcaptures
NAME   TARGETS   CAPTURING   DONE   FAILED   AGE
sip    3         2           1               40s
```

## How a capture works

A pod cannot be asked to capture its own traffic - not without a sidecar, an
annotation or a restart, and not at all if it is already running. So the capture
happens beside it:

```console
$ kubectl -n webshark get pods -l webshark.io/capture=sip
NAME                          READY   STATUS    AGE
pcap-sip-pcscf-0-3f9c1a2      1/1     Running   12s
```

That pod is bound straight to the node the target is on - `nodeName`, so the
scheduler never sees it and a cordoned or tainted node cannot leave a capture
Pending - and it is `hostPID`, which is how it finds what to capture:

```sh
# every network namespace on the node, once each, by the inode behind
# /proc/<pid>/ns/net; the one holding one of the pod's addresses is the pod's
nsenter -t "$pid" -n ip -o addr show
```

Then `nsenter -t <pid> -n tcpdump` runs the capture in that namespace, so
`-i any` is every interface the pod has. No CRI socket, no host mount, nothing
to know about containerd or CRI-O: the addresses in `status.podIPs` are the
whole of what identifies the pod.

The pcap is never written down:

```
tcpdump -i any -U -w -  |  curl -T - webshark/api/file?f=<pod>-<ns>-<date>.pcap
```

which is webshark's own upload endpoint, streamed chunked. The file appears in
the captures list the moment tcpdump starts and grows while it runs - `-U` is
what makes that true - so a capture can be read in webshark while it is still
being taken. Nothing touches the node's filesystem, and nothing needs a
ReadWriteMany volume to be shared between the capture and the viewer.

Only tcpdump crosses into the target's network. curl stays in the capture pod,
the two joined by a fifo, so the upload goes out of the capture pod's own
address and is not itself in the capture.

The pod being captured is not touched at all: nothing is added to it, nothing is
left in it, and its namespace's pod-security level has no say in the matter. The
whole of it is a shell script in
[`internal/controller/sniffer.go`](internal/controller/sniffer.go), visible in
`kubectl get pod -o yaml` next to the container that is running it.

## PacketCapture

| field | |
|---|---|
| `namespaceSelector` | namespaces to look in. Left out: this object's own. `{}`: every one. |
| `podSelector` | pods by label. Left out: all of them, which is what `maxTargets` is for. |
| `podNames` | pods by name, and-ed with `podSelector`. |
| `interface` | what tcpdump listens on, `any` by default. |
| `filter` | a pcap filter, applied in the pod's own network - what it drops never crosses it. |
| `snaplen` | bytes per packet; 0 is the whole packet. |
| `duration` | the longest a capture runs. `5m` by default, 0 for until the pod dies. |
| `maxPackets` | ends a capture early after that many packets. |
| `maxTargets` | how many pods this object will *ever* touch. 10 by default. |
| `paused` | stop the captures; resuming starts new ones for the pods still there. |
| `websharkRef` / `websharkURL` | where the pcaps go. Left out: the only Webshark in the namespace, or in the cluster. |
| `image` | the capture image; it needs tcpdump, curl, nsenter and ip. Defaults to the operator's own. |
| `fileNamePrefix` | goes in front of `<pod>-<namespace>-<date>.pcap`. |

The status has a line per pod - the file it is writing, the state it is in, what
the API server said if the capture was refused, and the pod doing the capturing,
which is where `kubectl logs` will find what tcpdump had to say.

A PacketCapture keeps watching after it is applied: a pod created later that
matches - the next rollout, a scale-up, a crashlooping pod coming back - gets a
capture of its own, up to `maxTargets` over the life of the object. `paused:
true` stops that, and so does deleting it.

### How a capture ends

There is a pod to delete, so any of these end one:

| | |
|---|---|
| `duration` running out | the usual end, and the longest a capture can run |
| `maxPackets` | tcpdump stops itself |
| `paused: true` | ends every running capture; the object and its status stay |
| deleting the PacketCapture | the same, and then the object goes |
| the target no longer running | the operator ends that one capture |
| `kubectl delete pod` on the capture pod | ends that one too |

The stop is a clean one. The kubelet's SIGTERM becomes a SIGINT to tcpdump,
which flushes what it has and closes the fifo; curl finishes the POST; webshark
has a whole file. Pausing stops a capture rather than suspending it - a pcap
being streamed cannot be picked up where it left off - so resuming starts a new
capture, in a new file, for each pod still running.

A target on its way out goes on being captured until it has actually gone: a pod
says some of its most interesting things while it shuts down.

A capture pod stays after it finishes - it is the record of what happened, and
`kubectl logs` on it is tcpdump's own account - until the PacketCapture is
deleted, which takes them with it. That is what the `webshark.io/captures`
finalizer is for, and the only thing it does.

### What a namespace has to allow

The namespace being captured: nothing. Nothing is created in it, so it can
enforce the **restricted** pod-security standard and be captured all the same.

The operator's own namespace: everything. A capture pod is `hostPID` and adds
`CAP_SYS_ADMIN` (`setns` into another namespace) and `CAP_SYS_PTRACE` (reading
`/proc/<pid>/ns` of a process that is not its own) to the `CAP_NET_RAW` and
`CAP_NET_ADMIN` tcpdump needs. It is not `privileged`: no devices, no host
mounts, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`,
`seccompProfile: RuntimeDefault`, no service account token. But `hostPID` plus
`CAP_SYS_ADMIN` is root on that node in all but name, so the namespace has to be
**privileged**:

```sh
kubectl label ns webshark pod-security.kubernetes.io/enforce=privileged
```

Without it the capture is refused, and the refusal appears in the
PacketCapture's status rather than anywhere subtle:

```
pods "pcap-sip-pcscf-0-3f9c1a2" is forbidden: violates PodSecurity
"baseline:latest": non-default capabilities (container "tcpdump" must not
include "NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYS_PTRACE" in
securityContext.capabilities.add), host namespaces (hostPID=true)
```

That is the trade: one namespace that can reach the node, in exchange for every
captured namespace needing nothing at all.

## Webshark

The deployment the captures go to, and everything around it: a
PersistentVolumeClaim for `/captures`, a Service, and an Ingress if asked for.
All of them are owned by the Webshark, so deleting it deletes them.

| field | |
|---|---|
| `image` | `ghcr.io/lyatanski/webshark:latest` by default. |
| `storage` | `size`, `storageClassName`, `existingClaim`, or `emptyDir: true` to keep the captures in the pod. |
| `service` | `type` and `port`. |
| `ingress` | `enabled`, `className`, `host`, `path`, `annotations`, `tlsSecretName`. |
| `env` | `SHARKD_SESSIONS`, `SHARKD_IDLE`, `SCAN_FRAMES` - see webshark's own README. |
| `resources` | sharkd holds a dissected capture in memory: this limit is what decides how large a file can be opened. |

`status.url` is where to read them - the ingress if there is one, the service
otherwise - and `status.serviceURL` is always the in-cluster one, which is what
the captures upload to.

## The page

The operator serves one, on `:8080`: pick a namespace, tick pods or type a label
selector, give it a filter and press Capture. It creates PacketCapture objects
and reads their status back, so a capture started there is the same object
`kubectl apply` would have made, and the capture files link straight into
webshark.

A capture shows in the **capture** column against the pod it is capturing, even
though it is not in it, and **pause** really does stop it - resuming starts a new
capture, in a new file.

```sh
kubectl -n webshark port-forward svc/ws-webshark-operator 8080:80
```

webshark itself opens in the page, over the whole window, with the captures a
close away behind it - the `open` link in the header for its capture list, and
every capture file for that file. It is not a window of its own because it does
not need one: the operator serves each Webshark under its own origin, at
`/webshark/<namespace>/<name>/`, and proxies it to the service from there. So
whatever reached this page reaches webshark - the port-forward above, a
NodePort, an ingress - and there is no second address to get right, which is
what there was when the page pointed at webshark's own port on the page's own
host and that was only ever a matched pair of port-forwards. Ctrl-click, or the
link in the viewer's bar, opens the same address in a tab of its own.

Nothing is rewritten in what comes back: every URL webshark asks for is relative
to the page it was loaded from, so it asks under that path by itself. Captures
still upload to the service directly - the proxy is for the browser, and a
Webshark with an ingress is still reachable at it.

Nothing in it asks who you are, and anyone who can reach it can read any pod's
traffic. It is a ClusterIP for that reason; put something that authenticates in
front of any ingress.

## What the operator is allowed to do

Cluster-wide, only to read: pods and namespaces, so it can find what a selector
picked. It cannot write to any namespace but its own - creating the capture pods
is a namespaced Role, because that is the only place one is ever made, and the
permission worth reading twice is therefore on that namespace and not on the
cluster. The rest is owning the deployment, service, claim and ingress behind
each Webshark. See
[`config/rbac/role.yaml`](config/rbac/role.yaml), which is generated from the
markers on the controllers. The chart's roles are hand-written rather than
copied from it - it splits leader election out into a namespaced Role, where one
flat ClusterRole is all controller-gen can emit - so `make verify-rbac` compares
the two by what they grant.

It does not watch pods. Pods are read straight from the API server and a
PacketCapture with anything running requeues itself every `--poll` (10s), an
idle one every `--idle-poll` (30s) to notice pods that have since been created -
a capture lasts minutes, and an informer over every pod in the cluster is the
largest thing a small operator usually is.

## Working on it

There is no Go toolchain on the development machine this was written on, so
everything runs in docker - see the [Makefile](Makefile):

```sh
make generate     # deepcopy, CRDs, RBAC - and the CRDs into the chart
make test         # gofmt, go vet, go test
make verify-rbac  # the chart's roles still grant what the markers ask for
make image        # docker build
make kind         # build, load into a kind cluster, restart the operator in it
```

End to end, against a throwaway cluster:

```sh
kind create cluster --name webshark
docker build -t webshark-operator:dev operator
kind load docker-image webshark-operator:dev --name webshark
helm install ws charts/webshark-operator -n webshark --create-namespace \
    --set image.repository=webshark-operator --set image.tag=dev
kubectl label ns webshark pod-security.kubernetes.io/enforce=privileged
kubectl apply -f operator/examples/packetcapture.yaml
```

The page is served off disk with `WEB=<dir>`, the same as webshark itself, so
`internal/ui/web` can be edited without a rebuild.
