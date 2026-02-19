CONTAINER_RUNTIME ?= "podman"

.PHONY: up
up: keycloak-certificate keycloak generate-config webhook cluster token

KEYCLOAK_IMAGE ?= "quay.io/keycloak/keycloak:latest"
KEYCLOAK_CONTAINER_NAME ?= "keycloak"
KEYCLOAK_ADMIN_USERNAME ?= "admin"
KEYCLOAK_ADMIN_PASSWORD ?= "admin"
.PHONY: keycloak
keycloak:
	${CONTAINER_RUNTIME} stop ${KEYCLOAK_CONTAINER_NAME} || true
	${CONTAINER_RUNTIME} wait ${KEYCLOAK_CONTAINER_NAME} || true
	${CONTAINER_RUNTIME} run -d --rm --name ${KEYCLOAK_CONTAINER_NAME} -p 127.0.0.1:8443:8443 --network=kind \
		-e KC_BOOTSTRAP_ADMIN_USERNAME=${KEYCLOAK_ADMIN_USERNAME} \
		-e KC_BOOTSTRAP_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD} \
		-e KC_HTTPS_CERTIFICATE_FILE=/certs/cert.pem \
		-e KC_HTTPS_CERTIFICATE_KEY_FILE=/certs/key.pem \
		-v $(shell pwd)/certs:/certs/ \
		-v $(shell pwd)/keycloak:/opt/keycloak/data/import/ \
		${KEYCLOAK_IMAGE} start-dev --import-realm

.PHONY: keycloak-certificate
keycloak-certificate:
	rm -rf certs/*
	mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -sha256 -days 365 -nodes -subj "/C=US/ST=NorthCarolina/L=Raleigh/O=Red Hat/OU=OpenShift/CN=keycloak" -addext "subjectAltName=DNS:keycloak"

.PHONY: build
build:
	mkdir -p bin
	go build -o bin/padlok main.go

IMAGE_TAG ?= "quay.io/rh_ee_bpalmer/padlok:latest"
.PHONY: image
image:
	${CONTAINER_RUNTIME} build -t ${IMAGE_TAG} .

CLIENT_ID ?= "k8s-client"
ISSUER ?= "https://keycloak:8443/realms/k8s"
.PHONY: token
token:
	${CONTAINER_RUNTIME} run --rm --network=kind ${IMAGE_TAG} oauth --issuer ${ISSUER} --client-id ${CLIENT_ID}

WEBHOOK_CONTAINER_NAME ?= padlok
.PHONY: webhook
webhook:
	${CONTAINER_RUNTIME} stop ${WEBHOOK_CONTAINER_NAME} || true
	${CONTAINER_RUNTIME} wait ${WEBHOOK_CONTAINER_NAME} || true
	${CONTAINER_RUNTIME} run -d --rm --name ${WEBHOOK_CONTAINER_NAME} --network=kind \
		-v $(shell pwd)/cfg/config.yaml:/cfg/config.yaml:Z \
		${IMAGE_TAG} run --config=/cfg/config.yaml

define CONFIG_TEMPLATE
apiVersion: everettraven.github.io/v1alpha1
kind: AuthenticationConfiguration
jwt:
  - issuer:
      url: https://keycloak:8443/realms/k8s
      audiences:
        - k8s-client
      certificateAuthority: |
$${KEYCLOAK_CERTIFICATE_AUTHORITY}
    claimMappings:
      username:
       claim: "preferred_username"
       prefix: ""
      groups:
        expression: "claims.groups.split(',')"
    externalClaimsSource:
      authentication:
        type: RequestProvidedToken
      tls:
        ca: |
$${KEYCLOAK_CERTIFICATE_AUTHORITY}
      sources:
        - url:
            base: https://keycloak:8443
            pathExpression: "['realms', 'k8s', 'protocol', 'openid-connect', 'userinfo']"
          mappings:
            - name: groups
              expression: "response.groups.join(',')"
endef
export CONFIG_TEMPLATE

.PHONY: generate-config
generate-config:
	rm -rf cfg/*
	mkdir -p cfg
	echo "$${CONFIG_TEMPLATE}" > cfg/config-templ.yaml
	export KEYCLOAK_CERTIFICATE_AUTHORITY=$$(sed 's/^/          /' certs/cert.pem); \
	envsubst < cfg/config-templ.yaml > cfg/config.yaml
	rm -f cfg/config-templ.yaml

.PHONY: cluster
cluster:
	kind delete cluster
	kind create cluster --config kind/config.yaml
