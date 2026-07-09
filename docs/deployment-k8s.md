# Kubernetes Deployment Guide

This guide describes how to deploy AccessGate to Kubernetes using the manifest in `deploy/k8s/accessgate.yaml`.

The included manifest is intentionally small and geared toward a single-node or small k3s-style environment. Review and adapt hostnames, node selectors, ingress, storage class, TLS, and image distribution before using it in a real environment.

## Prerequisites

- A Kubernetes cluster with `kubectl` access.
- A working ingress controller if you want to expose `ACCESSGATE_PUBLIC_URL` through HTTP(S).
- Persistent storage for the `accessgate-data` PVC.
- A container image available to the node that runs the AccessGate pod.
- A strong bootstrap API key for initial API access.

## 1. Review the Manifest

Open:

```bash
deploy/k8s/accessgate.yaml
```

Important values to review:

```yaml
nodeSelector:
  kubernetes.io/hostname: server-b

image: localhost/accessgate:0.1.0
imagePullPolicy: Never

ACCESSGATE_PUBLIC_URL: https://accessgate.example.com
ACCESSGATE_TLS_MODE: disabled-local
```

For your own cluster, change at least:

- `kubernetes.io/hostname`
- image name and pull policy
- ingress hostname
- `ACCESSGATE_PUBLIC_URL`
- `ACCESSGATE_TLS_MODE`
- storage class if your cluster does not use `local-path`

## 2. Create the Bootstrap Secret

Generate a strong key and store it as a Kubernetes secret:

```bash
kubectl create namespace accessgate

kubectl -n accessgate create secret generic accessgate-bootstrap \
  --from-literal=api-key="$(openssl rand -base64 32)"
```

If you already have the namespace from the manifest, `kubectl create namespace` may fail. That is fine; use `kubectl get namespace accessgate` to confirm it exists.

Keep this key secret. It can bootstrap API access and should not be committed, printed in logs, or shared.

## 3. Build the Linux Binary

For an ARM64 k3s node:

```bash
mkdir -p build/agents

GOOS=linux GOARCH=arm64 go build -o build/accessgate-linux-arm64 ./cmd/accessgate
GOOS=linux GOARCH=arm64 go build -o build/agents/accessgate-agent-linux-arm64 ./cmd/accessgate
GOOS=linux GOARCH=amd64 go build -o build/agents/accessgate-agent-linux-amd64 ./cmd/accessgate
```

For an AMD64 node, change the server binary build to `GOARCH=amd64`.

## 4. Build an Image Tar

The repository includes a small helper that creates a Docker-compatible image tar without requiring Docker:

```bash
python scripts/make-image-tar.py \
  --binary build/accessgate-linux-arm64 \
  --agents-dir build/agents \
  --image localhost/accessgate:0.1.0 \
  --out build/accessgate-0.1.0-arm64.tar
```

The helper currently writes an ARM64 image config. If you deploy to AMD64, update the helper or use your normal container build pipeline.

## 5. Import the Image on k3s

If the manifest uses:

```yaml
image: localhost/accessgate:0.1.0
imagePullPolicy: Never
```

then the image must exist on the node selected by `nodeSelector`.

Example for k3s:

```bash
scp build/accessgate-0.1.0-arm64.tar <node>:/tmp/accessgate-0.1.0-arm64.tar

ssh <node> 'sudo k3s ctr images import /tmp/accessgate-0.1.0-arm64.tar'

ssh <node> 'rm -f /tmp/accessgate-0.1.0-arm64.tar'
```

Alternative through Kubernetes node debug, if your cluster permissions allow it:

```bash
kubectl debug node/<node-name> --image=busybox:1.36 -- \
  chroot /host /usr/local/bin/k3s ctr images import /tmp/accessgate-0.1.0-arm64.tar
```

For production, prefer a proper registry and set `imagePullPolicy` accordingly.

## 6. Apply the Manifest

```bash
kubectl apply -f deploy/k8s/accessgate.yaml
```

Wait for rollout:

```bash
kubectl -n accessgate rollout status deployment/accessgate --timeout=120s
kubectl -n accessgate get pods -o wide
```

## 7. Smoke Test

Health endpoint:

```bash
curl https://accessgate.example.com/healthz
```

Informer:

```bash
curl https://accessgate.example.com/v1/informer
curl https://accessgate.example.com/v1/informer/agent-contract
```

Authenticated targets:

```bash
ACCESSGATE_API_TOKEN='<bootstrap-or-client-api-key>'

curl -H "Authorization: Bearer $ACCESSGATE_API_TOKEN" \
  https://accessgate.example.com/v1/targets
```

## 8. Create an Ops Login Link

The operator web panel is intentionally inactive unless an Ops Login Link or session is active.

Create a short-lived link from inside the running pod:

```bash
kubectl -n accessgate exec deploy/accessgate -- \
  /accessgate -opskey --operator <name> --ttl 1h \
  --base-url https://accessgate.example.com
```

Open the returned link once. After successful login, AccessGate redirects to `/ops` and stores only an operator session cookie.

## 9. Roll Out an Update

Build and import the new image with the same tag or a new tag.

If reusing the same local tag:

```bash
kubectl -n accessgate rollout restart deployment/accessgate
kubectl -n accessgate rollout status deployment/accessgate --timeout=120s
```

If changing the image tag:

```bash
kubectl -n accessgate set image deployment/accessgate \
  accessgate=<registry-or-local-image>:<tag>

kubectl -n accessgate rollout status deployment/accessgate --timeout=120s
```

## 10. Cleanup

Remove temporary image archives from build machines and nodes:

```bash
rm -f build/accessgate-*.tar
ssh <node> 'rm -f /tmp/accessgate-*.tar'
```

Do not delete the `accessgate-data` PVC unless you intentionally want to remove AccessGate state.

## Operational Notes

- `ACCESSGATE_PUBLIC_URL` controls generated Ops Login Links.
- `ACCESSGATE_DATA_DIR` should point at persistent storage.
- `ACCESSGATE_BOOTSTRAP_API_KEY` must come from a Kubernetes secret.
- `ACCESSGATE_TLS_MODE=disabled-local` is only suitable for trusted local/maintenance environments.
- Prefer HTTPS with valid certificates for anything beyond a trusted lab setup.
- Keep `/v1/informer` public if desired, but keep `/v1/targets` and lease endpoints authenticated.

## Troubleshooting

Check pod status:

```bash
kubectl -n accessgate get pods -o wide
kubectl -n accessgate describe deploy accessgate
kubectl -n accessgate logs deploy/accessgate --tail=100
```

Common issues:

- `ImagePullBackOff`: the node cannot pull the configured image.
- `ErrImageNeverPull`: `imagePullPolicy: Never` is set, but the image was not imported on the selected node.
- Ingress returns 404: ingress host or controller routing does not match.
- Ops panel returns `ops_ui_inactive`: create and open a fresh Ops Login Link.
- Authenticated API returns `authentication_required`: check the bearer token and secret configuration.
