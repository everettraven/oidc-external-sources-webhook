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

### /etc/hosts configuration
Because everything is run as containers on the `kind` network and Keycloak
doesn't dynamically modify the frontend url based on how it was accessed,
you'll need to add an `/etc/hosts` entry that matches:

```
127.0.0.1 keycloak
```

### Start everything
```sh
make image up
```

This will build the webhook image locally and spin up:
- A containerized and pre-configured Keycloak instance with:
    - Admin user with username + password of `admin`
    - A realm, `k8s`, with a user `testuser` (password `test`) who is a member of groups `one` and `two`
    - A public client for the realm with client-id `k8-client`
- A containerized instance of the webhook
- A KinD cluster configured with the webhook authenticator
- A temporary container executing the device code OAuth2 flow to obtain a token for authenticating against the cluster

### Update `kubeconfig` with new token-based context

1. Follow the device code flow steps to get the token (it will be printed to `stdout`)

2. Update `kubeconfig` with new token-based context using the fetched token. As an example:

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

### Make a request against the cluster

Now that everything is configured, you should be able to make a request to the
cluster and see that the token you received from Keycloak is mapped
to a cluster identity.

```sh
kubectl auth whoami
```

> [!NOTE]
> By default, this new user will have no permissions on the cluster.
> If you'd like to experiment with assigning permissions to this user
> and performing actions as this user, you will need to switch your
> context back to the `kind-kind` context and give the new user
> permissions by creating the appropriate RBAC resources.

Output should look something like:

```sh
ATTRIBUTE                                           VALUE
Username                                            testuser
Groups                                              [one two system:authenticated]
Extra: authentication.kubernetes.io/credential-id   [JTI=onrtro:81c6b4a1-0a37-fbcd-fe68-5cce2832ed91]
```
