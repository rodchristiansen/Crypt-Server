# Device Management API Implementation Plan

## Overview

This document outlines the implementation plan for a native REST API in Crypt-Server to manage devices (Computers) and their associated secrets. This API will allow authorized administrators to programmatically list, update, and delete devices.

## Current State

### Existing Endpoints
| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/checkin/` | POST | API Key | Client escrows a secret |
| `/verify/<serial>/<type>/` | GET | API Key | Client verifies secret exists |
| `/info/<computer_id>/` | GET | Session | Web UI - view computer info |
| `/admin/` | Web | Session/SSO | Django admin interface |

### Data Models
```
Computer
├── id (PK)
├── serial (unique)
├── username
├── computername
└── last_checkin

Secret (FK → Computer, cascade delete)
├── id (PK)
├── computer_id (FK)
├── secret (encrypted)
├── secret_type (recovery_key|password|unlock_pin)
├── date_escrowed
└── rotation_required

Request (FK → Secret, protected delete)
├── id (PK)
├── secret_id (FK)
├── requesting_user_id (FK)
├── approved
└── ... audit fields
```

## Proposed API Design

### Authentication
All management endpoints will require:
1. **API Key** (`X-API-Key` header) - same as existing `/checkin/` auth
2. **Management Permission** - optional: separate key or role-based access

### New Endpoints

#### 1. List Computers
```http
GET /api/v1/computers/
X-API-Key: <api-key>

Query Parameters:
  - search: Filter by serial or computername (optional)
  - page: Pagination (default: 1)
  - per_page: Results per page (default: 50, max: 200)

Response (200):
{
  "count": 538,
  "page": 1,
  "per_page": 50,
  "results": [
    {
      "id": 538,
      "serial": "MXQ544008H",
      "computername": "RODCHRISTIANSEN",
      "username": "ECUAD\\rchristiansen",
      "last_checkin": "2026-01-22T02:29:58.588Z",
      "secrets_count": 1
    }
  ]
}
```

#### 2. Get Computer Details
```http
GET /api/v1/computers/<serial>/
X-API-Key: <api-key>

Response (200):
{
  "id": 538,
  "serial": "MXQ544008H",
  "computername": "RODCHRISTIANSEN",
  "username": "ECUAD\\rchristiansen",
  "last_checkin": "2026-01-22T02:29:58.588Z",
  "secrets": [
    {
      "id": 784,
      "secret_type": "recovery_key",
      "date_escrowed": "2026-01-22T02:29:58.588Z",
      "rotation_required": false
    }
  ]
}

Response (404):
{"error": "Computer not found"}
```

#### 3. Update Computer
```http
PATCH /api/v1/computers/<serial>/
X-API-Key: <api-key>
Content-Type: application/json

{
  "computername": "New Computer Name",
  "username": "new.user"
}

Response (200):
{
  "id": 538,
  "serial": "MXQ544008H",
  "computername": "New Computer Name",
  "username": "new.user",
  ...
}
```

#### 4. Delete Computer
```http
DELETE /api/v1/computers/<serial>/
X-API-Key: <api-key>

Response (204): No Content

Response (409 - Conflict if pending requests):
{
  "error": "Cannot delete: 2 pending requests exist",
  "pending_requests": [123, 124]
}
```

#### 5. List Secrets for Computer
```http
GET /api/v1/computers/<serial>/secrets/
X-API-Key: <api-key>

Response (200):
{
  "computer_serial": "MXQ544008H",
  "secrets": [
    {
      "id": 784,
      "secret_type": "recovery_key",
      "date_escrowed": "2026-01-22T02:29:58.588Z",
      "rotation_required": false
    }
  ]
}
```

#### 6. Delete Specific Secret
```http
DELETE /api/v1/computers/<serial>/secrets/<secret_id>/
X-API-Key: <api-key>

Response (204): No Content
```

#### 7. Mark Secret for Rotation
```http
POST /api/v1/computers/<serial>/secrets/<secret_id>/rotate/
X-API-Key: <api-key>

Response (200):
{
  "id": 784,
  "rotation_required": true,
  "message": "Secret marked for rotation"
}
```

## Implementation Steps

### Phase 1: Core API Structure (Branch: `feature/device-management-api`)

#### Step 1.1: Create API Views Module
Create `server/api_views.py`:
```python
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator
from .models import Computer, Secret, Request
import json

@csrf_exempt
@require_http_methods(["GET"])
def list_computers(request):
    """List all computers with optional filtering."""
    search = request.GET.get('search', '')
    page = int(request.GET.get('page', 1))
    per_page = min(int(request.GET.get('per_page', 50)), 200)
    
    computers = Computer.objects.all()
    if search:
        computers = computers.filter(
            models.Q(serial__icontains=search) |
            models.Q(computername__icontains=search)
        )
    
    paginator = Paginator(computers, per_page)
    page_obj = paginator.get_page(page)
    
    results = [{
        'id': c.id,
        'serial': c.serial,
        'computername': c.computername,
        'username': c.username,
        'last_checkin': c.last_checkin.isoformat() if c.last_checkin else None,
        'secrets_count': c.secret_set.count()
    } for c in page_obj]
    
    return JsonResponse({
        'count': paginator.count,
        'page': page,
        'per_page': per_page,
        'results': results
    })

@csrf_exempt
@require_http_methods(["GET", "PATCH", "DELETE"])
def computer_detail(request, serial):
    """Get, update, or delete a computer."""
    try:
        computer = Computer.objects.get(serial=serial)
    except Computer.DoesNotExist:
        return JsonResponse({'error': 'Computer not found'}, status=404)
    
    if request.method == 'GET':
        return JsonResponse(_computer_to_dict(computer, include_secrets=True))
    
    elif request.method == 'PATCH':
        data = json.loads(request.body)
        for field in ['computername', 'username']:
            if field in data:
                setattr(computer, field, data[field])
        computer.save()
        return JsonResponse(_computer_to_dict(computer))
    
    elif request.method == 'DELETE':
        # Check for pending requests
        pending = Request.objects.filter(
            secret__computer=computer,
            approved__isnull=True
        )
        if pending.exists():
            return JsonResponse({
                'error': f'Cannot delete: {pending.count()} pending requests exist',
                'pending_requests': list(pending.values_list('id', flat=True))
            }, status=409)
        
        computer.delete()
        return JsonResponse({}, status=204)

def _computer_to_dict(computer, include_secrets=False):
    data = {
        'id': computer.id,
        'serial': computer.serial,
        'computername': computer.computername,
        'username': computer.username,
        'last_checkin': computer.last_checkin.isoformat() if computer.last_checkin else None,
    }
    if include_secrets:
        data['secrets'] = [{
            'id': s.id,
            'secret_type': s.secret_type,
            'date_escrowed': s.date_escrowed.isoformat(),
            'rotation_required': s.rotation_required
        } for s in computer.secret_set.all()]
    return data
```

#### Step 1.2: Create API URL Patterns
Create `server/api_urls.py`:
```python
from django.urls import path
from . import api_views

urlpatterns = [
    path('computers/', api_views.list_computers, name='api_list_computers'),
    path('computers/<str:serial>/', api_views.computer_detail, name='api_computer_detail'),
    path('computers/<str:serial>/secrets/', api_views.list_secrets, name='api_list_secrets'),
    path('computers/<str:serial>/secrets/<int:secret_id>/', api_views.secret_detail, name='api_secret_detail'),
    path('computers/<str:serial>/secrets/<int:secret_id>/rotate/', api_views.mark_rotation, name='api_mark_rotation'),
]
```

#### Step 1.3: Update Main URLs
Update `fvserver/urls.py`:
```python
# Add API routes
from server import api_urls
urlpatterns = [
    # ... existing patterns
    path("api/v1/", include(api_urls)),
]
```

#### Step 1.4: Update Middleware for API Paths
Update `server/middleware.py` to protect `/api/v1/`:
```python
PROTECTED_PATHS = ['/checkin/', '/verify/', '/api/v1/']
```

### Phase 2: Enhanced Features

#### Step 2.1: Add Logging/Audit Trail
Create audit log for all management API actions:
```python
class AuditLog(models.Model):
    action = models.CharField(max_length=50)  # CREATE, UPDATE, DELETE
    model_name = models.CharField(max_length=50)
    object_id = models.IntegerField()
    object_repr = models.CharField(max_length=200)
    changes = models.JSONField(null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    remote_addr = models.GenericIPAddressField()
```

#### Step 2.2: Rate Limiting (Optional)
Add rate limiting to prevent abuse:
```python
# Using django-ratelimit
from django_ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='100/h', method='GET', block=True)
def list_computers(request):
    ...
```

### Phase 3: Testing

#### Unit Tests
Create `server/tests/test_api.py`:
```python
from django.test import TestCase, Client
from server.models import Computer, Secret

class DeviceManagementAPITests(TestCase):
    def setUp(self):
        self.client = Client()
        self.api_key = 'test-api-key'
        self.headers = {'HTTP_X_API_KEY': self.api_key}
        
        # Create test computer
        self.computer = Computer.objects.create(
            serial='TEST123',
            username='testuser',
            computername='Test Computer'
        )
    
    def test_list_computers(self):
        response = self.client.get('/api/v1/computers/', **self.headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['count'], 1)
    
    def test_delete_computer(self):
        response = self.client.delete(
            f'/api/v1/computers/{self.computer.serial}/',
            **self.headers
        )
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Computer.objects.filter(serial='TEST123').exists())
```

## Security Considerations

1. **API Key Rotation**: Support for multiple API keys with expiration
2. **Audit Logging**: All delete/update operations logged with IP and timestamp
3. **Rate Limiting**: Prevent enumeration attacks
4. **HTTPS Only**: Enforce TLS in production
5. **Input Validation**: Sanitize all inputs, validate serial format

## Migration Path

1. Deploy API behind feature flag (`ENABLE_MANAGEMENT_API=false`)
2. Enable for internal testing
3. Update CryptEscrow client to use new API for unregistration
4. Enable in production
5. Update documentation

## Client Integration (CryptEscrow)

Add unregister command to Windows client:
```powershell
crypt.exe unregister --serial MXQ544008H --force
```

```csharp
// Commands/UnregisterCommand.cs
public class UnregisterCommand : Command
{
    public override async Task<int> ExecuteAsync(...)
    {
        var client = new CryptServerClient(config);
        var success = await client.DeleteDeviceAsync(serial);
        return success ? 0 : 1;
    }
}
```

## Timeline Estimate

| Phase | Task | Estimate |
|-------|------|----------|
| 1.1 | Create API views | 2 hours |
| 1.2 | URL routing | 30 min |
| 1.3 | Middleware update | 30 min |
| 1.4 | Basic testing | 1 hour |
| 2.1 | Audit logging | 2 hours |
| 2.2 | Rate limiting | 1 hour |
| 3 | Full test suite | 2 hours |
| - | Documentation | 1 hour |
| **Total** | | **~10 hours** |

## Files to Create/Modify

### New Files
- `server/api_views.py` - API view functions
- `server/api_urls.py` - API URL patterns
- `server/tests/test_api.py` - API tests
- `docs/API-REFERENCE.md` - API documentation

### Modified Files
- `server/middleware.py` - Add `/api/v1/` to protected paths
- `server/models.py` - Add AuditLog model (Phase 2)
- `fvserver/urls.py` - Include API URLs
- `setup/requirements.txt` - Add django-ratelimit (Phase 2)

## Branch Strategy

```
main (current: SSO + API key auth)
  └── feature/device-management-api
       ├── Phase 1: Core API
       ├── Phase 2: Audit + Rate limiting
       └── Phase 3: Tests
```

## Open Questions

1. Should we support multiple API keys (one for clients, one for management)?
2. Do we need role-based access (read-only vs. admin)?
3. Should the API support bulk operations (delete multiple devices)?
4. Retention policy: Auto-delete devices not seen in X days?
