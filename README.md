# oidc-external-sources-webhook

This is an early-stage proof-of-concept that explores adding "external claim sources"
to the Kubernetes Structured Authentication Configuration for OIDC token authentication.

External claim sources is any URL that contains information to be used as claims during
the cluster identity claim mapping process.

The purpose of this is to enable fetching claims that are not stored in the JWT for
identity providers that do not implement distributed claims support.

>[!NOTE]
>This project is in the extremely early stages of development and is not
>guaranteed to work. Breaking changes may be introduced at any time.

## Quick Start

This quick start is specifically for development purposes.

### Clone the repository
```sh
git clone github.com/everettraven/oidc-external-sources-webhook.git
```

### Build the webhook container image
```sh
podman build -t {tag} -f Dockerfile .
```

### Run the webhook container on the `kind` network
```sh
podman run --rm --name authnwebhook -d {tag}
```

### Create the KinD cluster
```sh
kind create cluster --config kind-config.yaml
```

### Update `kubeconfig` with new context
```yaml
apiVersion: v1
contexts:
...
- context:
    cluster: kind-kind
    user: token-user
  name: token-kind
current-context: token-kind
kind: Config
users:
...
- name: token-user
  user:
    token: blah
```
