"""
API Key Authentication Middleware for Crypt Server.

This middleware protects the /checkin/ and /verify/ API endpoints
with API key authentication while leaving the web UI accessible
for SSO/session-based authentication.

Configuration:
    Set the CRYPT_API_KEY environment variable to enable API key authentication.
    If not set, the endpoints remain open (backward compatible).

    To rotate the key without failing clients that still hold the old one, set
    CRYPT_API_KEY to the new key and CRYPT_API_KEY_PREVIOUS to the old key. Both
    are accepted until CRYPT_API_KEY_PREVIOUS is removed.

Usage:
    Clients must include the API key in the X-API-Key header:
    curl -X POST https://crypt.example.com/checkin/ \
        -H "X-API-Key: your-secret-key" \
        -d "serial=ABC123&recovery_password=..."
"""
import os
import hmac
import logging
from django.http import JsonResponse
from django.conf import settings

logger = logging.getLogger(__name__)


class APIKeyAuthMiddleware:
    """
    Middleware to authenticate API requests using an API key.
    
    Only applies to:
        - /checkin/ (POST)
        - /verify/<serial>/<secret_type>/ (GET)
    
    The API key is read from:
        1. CRYPT_API_KEY environment variable
        2. settings.CRYPT_API_KEY (if defined in settings.py)

    CRYPT_API_KEY_PREVIOUS (environment or settings) is accepted as well, for the
    length of a key rotation. It has no effect unless CRYPT_API_KEY is set.

    If no API key is configured, requests are allowed through (backward compatible).
    """
    
    # Paths that require API key authentication
    PROTECTED_PATHS = ['/checkin/', '/verify/']
    
    # Header name for API key
    API_KEY_HEADER = 'HTTP_X_API_KEY'  # Django converts X-API-Key to HTTP_X_API_KEY
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.api_key = self._get_api_key()
        self.previous_api_key = self._get_api_key("CRYPT_API_KEY_PREVIOUS") if self.api_key else None

        if self.api_key:
            logger.info("API key authentication enabled for /checkin/ and /verify/ endpoints")
            if self.previous_api_key:
                logger.warning(
                    "CRYPT_API_KEY_PREVIOUS is set: the previous API key is still accepted. "
                    "Remove it once every client has the current key."
                )
        else:
            logger.warning(
                "No CRYPT_API_KEY configured. API endpoints are UNPROTECTED. "
                "Set CRYPT_API_KEY environment variable to enable authentication."
            )
    
    def _get_api_key(self, name='CRYPT_API_KEY'):
        """Get an API key from environment or settings, or None when unset or blank."""
        # Try environment variable first
        api_key = os.environ.get(name)
        if api_key and api_key.strip():
            return api_key.strip()

        # Fall back to settings
        return (getattr(settings, name, '') or '').strip() or None

    def _is_valid_key(self, request_api_key, path):
        """Constant-time comparison against the current key and, during a rotation, the previous one."""
        valid = hmac.compare_digest(request_api_key.encode(), self.api_key.encode())
        if self.previous_api_key:
            if hmac.compare_digest(request_api_key.encode(), self.previous_api_key.encode()):
                logger.info("Previous API key used for %s", path)
                valid = True
        return valid
    
    def _is_protected_path(self, path):
        """Check if the request path requires API key authentication."""
        for protected in self.PROTECTED_PATHS:
            if path.startswith(protected):
                return True
        return False
    
    def __call__(self, request):
        # Only check protected API endpoints
        if self._is_protected_path(request.path):
            # If no API key is configured, allow request (backward compatible)
            if not self.api_key:
                return self.get_response(request)
            
            # Get API key from request header
            request_api_key = request.META.get(self.API_KEY_HEADER)
            
            if not request_api_key:
                logger.warning(
                    "API request to %s without API key from %s",
                    request.path,
                    request.META.get('REMOTE_ADDR', 'unknown')
                )
                return JsonResponse(
                    {'error': 'API key required. Include X-API-Key header.'},
                    status=401
                )
            
            # Validate API key (constant-time comparison to prevent timing attacks)
            if not self._is_valid_key(request_api_key, request.path):
                logger.warning(
                    "Invalid API key for %s from %s",
                    request.path,
                    request.META.get('REMOTE_ADDR', 'unknown')
                )
                return JsonResponse(
                    {'error': 'Invalid API key.'},
                    status=403
                )
            
            logger.debug("API key validated for %s", request.path)
        
        return self.get_response(request)
