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

### Setup Keycloak

1. Create self-signed certificate for Keycloak

```sh
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes
```

> [!NOTE]
> Make sure to set the Common Name (CN) to `keycloak`

2. Run Keycloak with self-signed certificate

```sh
podman run --name keycloak -p 127.0.0.1:8080:8443 --network=kind \
        -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=change_me \
        -e KC_HTTPS_CERTIFICATE_FILE=/certs/cert.pem -e KC_HTTPS_CERTIFICATE_KEY_FILE=/certs/key.pem \
        -v $(pwd)/cert.pem:/certs/cert.pem -v $(pwd)/key.pem:/certs/key.pem\
        quay.io/keycloak/keycloak:latest \
        start-dev
```

3. Configure a new Keycloak realm and client

> [!NOTE]
> Make sure to set the Frontend URL for the realm to `https://keycloak:8443`

4. Add a new user to the realm

### Run the webhook container on the `kind` network

1. Create the configuration file:

```json
{
    "issuer": {
        "url": "https://keycloak:8443/realms/{realm}",
        "audiences": [
            "account"
        ],
        "certificateAuthority": "{cert.pem contents}"
    },
    "claimMappings": {
        "username": {
            "claim": "preferred_username",
            "prefix": ""
        }
    }
}
```

```sh
podman run --rm --name authnwebhook -d --network=kind -v $(pwd)/keycloak-config.json:/cfg/keycloak-config.json {tag} -- --config=/cfg/keycloak-config.json
```

### Create the KinD cluster
```sh
kind create cluster --config kind-config.yaml
```

### Update `kubeconfig` with new token-based context

1. Fetch token for user:

```sh
curl -k --data "grant_type=password&client_id={CLIENT_ID}&client_secret={CLIENT_SECRET}&username={USERNAME}&password={PASSWORD}" https://127.0.0.1:8080/realms/{realm}/protocol/openid-connect/token
```

2. Update `kubeconfig` with new token-based context using the fetched token

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
    token: {token}
```
