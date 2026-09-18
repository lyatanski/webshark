# webshark-operator

Installs the operator, its CRDs, and a webshark for captures to land in.

```sh
helm install ws charts/webshark-operator -n webshark --create-namespace
```

Then either the page:

```sh
kubectl -n webshark port-forward svc/ws-webshark-operator 8080:80
```

or a capture object:

```sh
kubectl apply -f - <<'YAML'
apiVersion: webshark.io/v1alpha1
kind: PacketCapture
metadata: {name: sip, namespace: ims}
spec:
  podSelector: {matchLabels: {app: pcscf}}
  filter: udp port 5060
  duration: 5m
YAML
```

What the objects mean is in [operator/README.md](../../operator/README.md).

The one thing worth knowing before the first capture: tcpdump runs in a pod of
the operator's own, on the node of the pod being captured, and that pod is
`hostPID` with `CAP_SYS_ADMIN`. It is created in this release's namespace, which
therefore has to allow it:

```sh
kubectl label ns webshark pod-security.kubernetes.io/enforce=privileged
```

No other namespace needs anything at all - the pods being captured are not
touched, so they can enforce **restricted** and be captured all the same.

## Values

| | | |
|---|---|---|
| `image.repository` | `ghcr.io/lyatanski/webshark-operator` | the operator, and by default the capture pods too |
| `snifferImage` | the operator's own image | override where the captured pods' nodes pull from somewhere else |
| `replicaCount` / `leaderElect` | `1` / `false` | turn leader election on for more than one |
| `poll` / `idlePoll` | `10s` / `30s` | how often a running capture is re-read, and an idle one looks for new pods |
| `rbac.create` | `true` | a read-only ClusterRole over pods and namespaces, and the namespaced Role that creates the capture pods |
| `ui.enabled` | `true` | the page |
| `ui.service` / `ui.ingress` | ClusterIP :80 / off | **the page has no authentication** - see below |
| `metrics.enabled` | `false` | controller-runtime metrics on `metrics.port` |
| `webshark.enabled` | `true` | create a Webshark object for captures to go to |
| `webshark.storage` | 10Gi claim | or `emptyDir: true`, or `existingClaim` |
| `webshark.service` / `webshark.ingress` | ClusterIP :8085 / off | how webshark itself is reached |
| `webshark.resources` | 2Gi limit | sharkd holds a dissected capture in memory: this is what bounds the size of file that can be opened |
| `webshark.env` | `[]` | `SHARKD_SESSIONS`, `SHARKD_IDLE`, `SCAN_FRAMES` |

Anyone who can reach the page can read any pod's traffic, and anyone who can
reach webshark can read every capture taken. Neither asks who is knocking, so
both are ClusterIP services by default; an ingress in front of either wants
something that does.

## CRDs

They are in `crds/`, which helm installs before anything else and then leaves
alone - `helm upgrade` will not touch them, and `helm uninstall` will not delete
them, because deleting a CRD deletes every object of that kind with it. To take
a new version:

```sh
kubectl apply -f charts/webshark-operator/crds/
```

`--skip-crds` installs the chart without them.
