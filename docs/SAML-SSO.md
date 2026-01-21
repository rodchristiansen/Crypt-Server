# SAML SSO Configuration

Crypt Server supports SAML 2.0 Single Sign-On for integration with enterprise identity providers.

## Supported Identity Providers

- Microsoft Entra ID (Azure AD)
- Okta
- OneLogin
- Any SAML 2.0 compliant IdP

## Quick Start

### 1. Enable SAML

Set the `SAML_ENABLED` environment variable:

```bash
SAML_ENABLED=true
```

### 2. Configure Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `HOST_NAME` | Your Crypt Server URL | `https://crypt.example.com` |
| `SAML_METADATA_URL` | IdP metadata URL | See provider examples below |

### 3. Provider-Specific Configuration

#### Microsoft Entra ID (Azure AD)

```bash
SAML_ENABLED=true
HOST_NAME=https://crypt.example.com
SAML_METADATA_URL=https://login.microsoftonline.com/YOUR_TENANT_ID/federationmetadata/2007-06/federationmetadata.xml?appid=YOUR_APP_ID
```

**Entra ID App Registration:**
1. Create new Enterprise Application (SAML)
2. Set Identifier (Entity ID): `https://crypt.example.com/saml/metadata`
3. Set Reply URL (ACS): `https://crypt.example.com/saml/acs/`
4. Set Sign-on URL: `https://crypt.example.com/saml/login/`
5. Configure Claims:
   - `name` → `user.mail` (Required)
   - `givenName` → `user.givenname` (Optional)
   - `surname` → `user.surname` (Optional)

#### Okta

```bash
SAML_ENABLED=true
HOST_NAME=https://crypt.example.com
SAML_METADATA_URL=https://your-org.okta.com/app/YOUR_APP_ID/sso/saml/metadata
```

#### OneLogin

```bash
SAML_ENABLED=true
HOST_NAME=https://crypt.example.com
SAML_METADATA_URL=https://your-org.onelogin.com/saml/metadata/YOUR_APP_ID
```

## Environment Variables Reference

### Required

| Variable | Description |
|----------|-------------|
| `SAML_ENABLED` | Set to `true` to enable SAML |
| `HOST_NAME` | Full URL of your Crypt Server |
| `SAML_METADATA_URL` | URL to fetch IdP metadata |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `SAML_SP_ENTITY_ID` | `{HOST_NAME}/saml/metadata` | Service Provider Entity ID |
| `SAML_IDP_ENTITY_ID` | (from metadata) | Override IdP Entity ID |
| `SAML_IDP_SSO_URL` | (from metadata) | Override SSO URL |
| `SAML_IDP_SLO_URL` | (from metadata) | Override Logout URL |
| `SAML_WANT_ASSERTIONS_SIGNED` | `true` | Require signed assertions |
| `SAML_WANT_RESPONSE_SIGNED` | `false` | Require signed responses |
| `SAML_LOG_LEVEL` | (none) | Set to `DEBUG` for verbose logging |

## SAML Endpoints

Once enabled, these endpoints are available:

| Endpoint | Purpose |
|----------|---------|
| `/saml/login/` | Initiate SSO login |
| `/saml/acs/` | Assertion Consumer Service (POST) |
| `/saml/metadata/` | SP Metadata (XML) |
| `/saml/sls/` | Single Logout Service |

## User Provisioning

SAML users are automatically created on first login. The email address from the SAML assertion is used as the username.

To grant admin access to SAML users:

```bash
docker exec -it crypt /bin/sh
python manage.py shell
```

```python
from django.contrib.auth.models import User
user = User.objects.get(username='user@example.com')
user.is_staff = True
user.is_superuser = True
user.save()
```

## Docker Compose Example

```yaml
services:
  crypt:
    image: ghcr.io/grahamgilbert/crypt-server:latest
    environment:
      HOST_NAME: https://crypt.example.com
      SAML_ENABLED: "true"
      SAML_METADATA_URL: "https://login.microsoftonline.com/TENANT/federationmetadata/2007-06/federationmetadata.xml?appid=APP_ID"
      FIELD_ENCRYPTION_KEY: "your-encryption-key"
    ports:
      - "8000:8000"
```

## Troubleshooting

### Enable Debug Logging

```bash
SAML_LOG_LEVEL=DEBUG
```

### Common Issues

**"No user identity found"**
- Verify the IdP is sending the email in the `name` or `email` attribute
- Check SAML response in browser developer tools (Network tab)

**"Signature validation failed"**
- Ensure `SAML_WANT_ASSERTIONS_SIGNED=true` matches your IdP configuration
- Try `SAML_WANT_RESPONSE_SIGNED=false` if IdP only signs assertions

**"Invalid ACS URL"**
- Verify Reply URL in IdP matches exactly: `https://your-host/saml/acs/`
- Note the trailing slash is required

### Verify Metadata

Test that your SP metadata is accessible:

```bash
curl https://crypt.example.com/saml/metadata/
```

## Keeping Local Login

SAML and local Django authentication work side-by-side. Access the standard login at `/login/` if needed.
