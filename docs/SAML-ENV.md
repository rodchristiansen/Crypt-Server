# Configuring SAML from the environment

SAML can be configured either from a YAML file (`SAML_CONFIG_FILE`, documented in
`saml-config.sample.yaml`) or entirely from environment variables. Most container platforms
deliver configuration as environment rather than as a mounted file, which is what these
variables are for.

Set `SAML_ENABLED=true` to use them. If `SAML_CONFIG_FILE` is also set, the file wins and
these are ignored; the server logs which source it used at startup.

## Required

- `HOST_NAME` - The server's public base URL, for example `https://crypt.example.edu`. A
  trailing slash is stripped. Assertion consumer and metadata URLs are built from it.
- One of `SAML_METADATA_URL` or `SAML_IDP_METADATA_PATH` - Where to fetch or read the
  identity provider's metadata. A URL is usually easier; Entra ID, Okta and OneLogin all
  publish one.

## Service provider identity

- `SAML_SP_ENTITY_ID` - The entity ID this server presents. Defaults to the value the SAML
  library derives from `HOST_NAME`.
- `SAML_CERTIFICATE_PATH`, `SAML_PRIVATE_KEY_PATH` - The service provider keypair. Required
  only when `SAML_SIGN_REQUEST` is true, or when the identity provider encrypts assertions.
- `SAML_SIGN_REQUEST` - Sign authentication requests. Default: `false`.
- `SAML_ALLOW_IDP_INITIATED` - Accept unsolicited assertions, which is what an identity
  provider's application tile sends. Default: `true`.

## Identity mapping

- `SAML_USE_NAME_ID_AS_USERNAME` - Use the NameID as the username. Default: `true`.
- `SAML_USERNAME_ATTRIBUTE` - The attribute to take the username from when NameID is not
  being used.
- `SAML_CREATE_UNKNOWN_USER` - Create an account on first sign-in. Default: `true`.
- `SAML_AUTH_SOURCE` - The `auth_source` recorded on accounts created this way.
  Default: `saml`.
- `SAML_LOCAL_LOGIN_ENABLED` - Whether accounts created this way may also sign in with a
  local password. Default: `false`.
- `SAML_MUST_RESET_PASSWORD` - Whether accounts created this way must set a password on
  first local sign-in. Default: `false`.

## Permissions from group claims

- `SAML_GROUPS_ATTRIBUTE` - The assertion attribute carrying group membership.
  Default: `memberOf`.
- `SAML_STAFF_GROUPS` - Comma-separated groups whose members get `is_staff`.
- `SAML_SUPERUSER_GROUPS` - Comma-separated groups whose members get staff and approval.
- `SAML_CAN_APPROVE_GROUPS` - Comma-separated groups whose members get `can_approve`.

## Endpoint paths

Override only if the identity provider was registered against different paths.

- `SAML_DEFAULT_REDIRECT_URI` - Where to land after sign-in. Default: `/`.
- `SAML_METADATA_URL_PATH` - Default: `/saml2/metadata/`.
- `SAML_ACS_URL_PATH` - Default: `/saml2/acs/`.
- `SAML_SLO_URL_PATH` - Default: `/saml2/ls/`.

## Example

``` bash
SAML_ENABLED=true
HOST_NAME=https://crypt.example.edu
SAML_METADATA_URL=https://login.microsoftonline.com/<tenant-id>/federationmetadata/2007-06/federationmetadata.xml?appid=<app-id>
SAML_GROUPS_ATTRIBUTE=http://schemas.microsoft.com/ws/2008/06/identity/claims/groups
SAML_STAFF_GROUPS=<group-object-id>
SAML_CAN_APPROVE_GROUPS=<group-object-id>
```

Group claims from Entra ID arrive as object IDs unless the application is configured to emit
group names, so the group lists above usually hold object IDs.
