"""
SAML SSO Configuration for Crypt-Server

This module provides SAML 2.0 Single Sign-On support using djangosaml2 and pysaml2.
Configuration is entirely environment variable-based for flexibility.

Supported Identity Providers:
- Microsoft Entra ID (Azure AD)
- Okta
- OneLogin
- Any SAML 2.0 compliant IdP

Enable by setting SAML_ENABLED=true in environment variables.
"""
import os
import saml2
import saml2.saml

# SP Configuration from environment
HOST_NAME = os.environ.get('HOST_NAME', 'https://localhost').rstrip('/')
SAML_SP_ENTITY_ID = os.environ.get('SAML_SP_ENTITY_ID', f'{HOST_NAME}/saml/metadata')

# IdP Configuration from environment
SAML_IDP_ENTITY_ID = os.environ.get('SAML_IDP_ENTITY_ID', '')
SAML_IDP_SSO_URL = os.environ.get('SAML_IDP_SSO_URL', '')
SAML_IDP_SLO_URL = os.environ.get('SAML_IDP_SLO_URL', '')
SAML_METADATA_URL = os.environ.get('SAML_METADATA_URL', '')

# Security options
SAML_WANT_ASSERTIONS_SIGNED = os.environ.get('SAML_WANT_ASSERTIONS_SIGNED', 'true').lower() == 'true'
SAML_WANT_RESPONSE_SIGNED = os.environ.get('SAML_WANT_RESPONSE_SIGNED', 'false').lower() == 'true'

# Debug level (0=off, 1=on)
SAML_DEBUG = 1 if os.environ.get('SAML_LOG_LEVEL', '').upper() == 'DEBUG' else 0

# Build metadata configuration
# Prefer remote metadata URL if provided, otherwise use inline IdP config
_metadata_config = {}
if SAML_METADATA_URL:
    _metadata_config = {
        'remote': [
            {'url': SAML_METADATA_URL},
        ],
    }

# SAML Configuration Dictionary for pysaml2
SAML_CONFIG = {
    'entityid': SAML_SP_ENTITY_ID,
    'service': {
        'sp': {
            'name': 'Crypt Server',
            'name_id_format': saml2.saml.NAMEID_FORMAT_EMAILADDRESS,
            'endpoints': {
                'assertion_consumer_service': [
                    (f'{HOST_NAME}/saml/acs/', saml2.BINDING_HTTP_POST),
                ],
                'single_logout_service': [
                    (f'{HOST_NAME}/saml/sls/', saml2.BINDING_HTTP_REDIRECT),
                    (f'{HOST_NAME}/saml/sls/', saml2.BINDING_HTTP_POST),
                ],
            },
            'required_attributes': ['email'],
            'optional_attributes': ['givenName', 'surname', 'displayName'],
            'want_assertions_signed': SAML_WANT_ASSERTIONS_SIGNED,
            'want_response_signed': SAML_WANT_RESPONSE_SIGNED,
            'allow_unsolicited': True,
            'idp': {
                SAML_IDP_ENTITY_ID: {
                    'single_sign_on_service': {
                        saml2.BINDING_HTTP_REDIRECT: SAML_IDP_SSO_URL,
                        saml2.BINDING_HTTP_POST: SAML_IDP_SSO_URL,
                    },
                    'single_logout_service': {
                        saml2.BINDING_HTTP_REDIRECT: SAML_IDP_SLO_URL,
                    },
                },
            } if SAML_IDP_ENTITY_ID else {},
        },
    },
    'metadata': _metadata_config,
    'debug': SAML_DEBUG,
}

# djangosaml2 specific settings
# Attribute mapping: Maps SAML attributes to Django user model fields
# Microsoft Entra ID sends email in 'name' attribute by default
# Okta/OneLogin typically use 'email' attribute
SAML_ATTRIBUTE_MAPPING = {
    'name': ('email', 'username'),      # Microsoft Entra ID
    'email': ('email', 'username'),     # Okta, OneLogin
    'givenName': ('first_name',),
    'surname': ('last_name',),
    'firstName': ('first_name',),       # Okta format
    'lastName': ('last_name',),         # Okta format
}

# User provisioning settings
SAML_CREATE_UNKNOWN_USER = True
SAML_DJANGO_USER_MAIN_ATTRIBUTE = 'username'
SAML_USE_NAME_ID_AS_USERNAME = False  # Use email from attributes, not NameID
SAML_DJANGO_USER_MAIN_ATTRIBUTE_LOOKUP = '__iexact'

# Session settings
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# URL configuration
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'
LOGIN_URL = '/saml/login/'
