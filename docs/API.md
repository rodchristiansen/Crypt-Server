# Crypt Server JSON API

Everything lives under `/api/v1`. The HTML routes and the two legacy client routes
(`POST /checkin/`, `GET /verify/<serial>/<type>/`) are unchanged, so shipped clients keep
working; the JSON equivalents below delegate to the same handlers.

Set `API_ENABLED=false` to leave the API unmounted.

## Principals

Three kinds of caller, with different ceilings.

| Principal | Credential | Ceiling |
|---|---|---|
| Device | `Authorization: Bearer ck_dev_…` | Escrow its own secret and read its own escrow state. Cannot hold `secrets:read` or `secrets:reveal`; the server rejects the grant rather than ignoring it. |
| Service | `Authorization: Bearer ck_svc_…` | Whatever scopes the token carries. |
| User | Session cookie, or `Bearer ck_pat_…` | The person's own `is_staff` / `can_approve`, intersected with the token's scopes. |

`X-API-Key` is accepted as an alias for `Authorization: Bearer`.

`CRYPT_API_KEY`, if set, is accepted as a shared key that grants `escrow:write` and nothing
else. It exists so a deployment already running the shared-key middleware can adopt
`/api/v1/escrow` before minting tokens.

### Scopes

```
escrow:write        computers:read      computers:write     computers:delete
secrets:read        secrets:rotate      secrets:reveal      requests:read
requests:write      requests:approve    users:read          users:write
audit:read          admin
```

`admin` implies every other scope. `secrets:reveal` is the only scope that returns plaintext
outside the approval workflow; every use of it writes an audit event tagged `break_glass`.

A signed-in person's scopes are derived from their permissions, not stored: everyone gets
`computers:read`, `secrets:read`, `requests:read` and `requests:write`; an approver also gets
`requests:approve`; staff also get the write, user-administration, audit and `admin` scopes.
`secrets:reveal` is never derived — a person reads a secret by raising a request and having
it approved.

### Tokens

Only the SHA-256 of a token's secret half is stored. The plaintext is returned exactly once,
by the endpoint that mints it. The `ck_<kind>_` prefix makes a leaked credential identifiable
and revocable by prefix.

Mint the first one from the command line:

``` bash
./crypt-server -create-token -token-name=reportmate -token-kind=service -token-scopes=computers:read
```

## Conventions

- Timestamps are RFC 3339 UTC.
- Collections return `{"count", "page", "per_page", "results": []}`. `per_page` caps at 200.
- Errors return `{"error": {"code", "message", "details"}}` with a stable machine-readable `code`.
- Unknown JSON fields are rejected, so a typo in a client payload is an error rather than a silent no-op.
- Computers are addressable by id or serial: `/computers/538` and `/computers/by-serial/ABC123` are the same resource.
- The two endpoints that return plaintext are rate limited per caller. Exceeding the limit
  returns `429` with a `Retry-After` header and a `retry_after_seconds` detail. Metadata
  reads are not limited.
- A caller authenticated by session cookie must send the CSRF token in `X-CSRF-Token` on
  unsafe methods. Bearer callers are exempt, since a browser never attaches a bearer token
  on its own.

## Meta

| Method | Path | Scope | Notes |
|---|---|---|---|
| GET | `/health` | none | Liveness. |
| GET | `/ready` | none | Pings the database. |
| GET | `/settings` | `admin` | Policy flags, scope and event vocabularies. |
| GET | `/stats` | `computers:read` | Fleet summary. |
| GET | `/metrics` | `computers:read` | Prometheus text. |

## Escrow

| Method | Path | Scope |
|---|---|---|
| POST | `/escrow` | `escrow:write` |
| GET | `/escrow/status?serial=&secret_type=` | `escrow:write` |
| POST | `/escrow/rotation-complete` | `escrow:write` |

``` json
POST /api/v1/escrow
{
  "serial": "ABC123",
  "username": "someone",
  "computer_name": "a-mac",
  "secret_type": "recovery_key",
  "secret": "XXXX-XXXX-XXXX-XXXX",
  "platform": "macos",
  "os_version": "26.1",
  "agent_version": "6.0.1",
  "hardware_uuid": "..."
}
```

`platform`, `os_version`, `agent_version` and `hardware_uuid` are optional. They are stored on
the computer record and are what make platform filtering and agent-version reporting possible.

The response reports `new_secret_escrowed`, matching the legacy `/checkin/` field, and
`rotation_required`, which tells the client whether to roll the key and escrow again.
`/escrow/rotation-complete` is how the client says it did, clearing the flag.

## Computers

| Method | Path | Scope |
|---|---|---|
| GET | `/computers` | `computers:read` |
| POST | `/computers` | `computers:write` |
| GET | `/computers.csv` | `computers:read` |
| GET | `/computers/stale?days=30` | `computers:read` |
| POST | `/computers:bulk-delete` | `computers:delete` |
| GET | `/computers/{id}` | `computers:read` |
| PATCH | `/computers/{id}` | `computers:write` |
| DELETE | `/computers/{id}` | `computers:delete` |
| GET | `/computers/{id}/secrets` | `secrets:read` |
| POST | `/computers/{id}/secrets` | `admin` |
| GET | `/computers/{id}/requests` | `requests:read` |
| GET | `/computers/{id}/audit` | `audit:read` |

Listing filters: `search`, `username`, `platform`, `secret_type`, `escrowed`,
`rotation_required`, `last_checkin_before`, `last_checkin_after`, `stale_days`, `sort`.
`sort` accepts `serial`, `username`, `computername`, `last_checkin` and `id`, each with a
leading `-` for descending order.

Deleting a computer with pending retrieval requests returns `409` and lists the request ids.
Repeat with `?force=true` to delete anyway.

## Secrets

| Method | Path | Scope |
|---|---|---|
| GET | `/secrets` | `secrets:read` |
| GET | `/secrets/{id}` | `secrets:read` |
| GET | `/secrets/{id}/value` | `secrets:reveal` |
| POST | `/secrets/{id}/rotation` | `secrets:rotate` |
| DELETE | `/secrets/{id}` | `admin` |

`/secrets/{id}/value` is break-glass retrieval: it returns the plaintext without an approved
request. It accepts `?reason=`, which is recorded. When `ROTATE_VIEWED_SECRETS` is set it also
flags the secret for rotation, exactly as the HTML retrieval screen does.

## Requests

| Method | Path | Scope |
|---|---|---|
| POST | `/requests` | `requests:write` |
| GET | `/requests` | `requests:read` |
| GET | `/requests/{id}` | `requests:read` |
| POST | `/requests/{id}/approve` | `requests:approve` |
| POST | `/requests/{id}/deny` | `requests:approve` |
| POST | `/requests/{id}/retrieve` | `requests:read` |
| DELETE | `/requests/{id}` | `requests:write` |

Listing filters: `status` (`pending`, `approved`, `denied`), `mine`, `secret_id`,
`computer_serial`, `requesting_user`, `current`.

Creating a request returns it already approved when the caller may approve and `APPROVE_OWN`
is set, matching the web UI. Otherwise an approver must decide it. Deciding a request twice
returns `409`.

`/requests/{id}/retrieve` returns the secret for an approved, still-current request belonging
to the caller, or to an approver. This is the normal way a person reads a secret.

Only the requester, or an admin, can cancel a pending request. A decided request cannot be
cancelled.

## Users

| Method | Path | Scope |
|---|---|---|
| GET | `/users/me` | any authenticated caller |
| POST | `/users/me/password` | any authenticated caller |
| GET | `/users` | `users:read` |
| POST | `/users` | `users:write` |
| GET | `/users/{id}` | `users:read` |
| PATCH | `/users/{id}` | `users:write` |
| DELETE | `/users/{id}` | `users:write` |
| POST | `/users/{id}/password` | `users:write` |
| POST | `/users/{id}/sessions:revoke` | `users:write` |

`/users/me` reports the caller's identity, permissions and effective scopes. It is the
endpoint a client should call first.

Passwords set through the API must be at least 12 characters. Revoking sessions invalidates
every session issued before that moment, which is what makes an offboarding take effect
immediately rather than at the next session expiry.

## Tokens

| Method | Path | Scope |
|---|---|---|
| GET | `/tokens` | `admin` |
| POST | `/tokens` | `admin` |
| GET | `/tokens/{id}` | `admin` |
| DELETE | `/tokens/{id}` | `admin` |
| POST | `/tokens/{id}/rotate` | `admin` |

``` json
POST /api/v1/tokens
{
  "name": "reportmate",
  "kind": "service",
  "scopes": ["computers:read", "secrets:read"],
  "expires_at": "2027-01-01T00:00:00Z"
}
```

The response carries `secret`, the only time the plaintext is ever returned. Rotating issues a
replacement with the same name, kind and scopes, then revokes the original.

## Audit

| Method | Path | Scope |
|---|---|---|
| GET | `/audit` | `audit:read` |
| GET | `/audit.csv` | `audit:read` |

Filters: `q`, `actor`, `action`, `target_user`, `target_type`, `from`, `to`.

Events recorded:

```
secret.escrowed   secret.updated    secret.viewed     secret.deleted
secret.rotation_flagged
request.created   request.approved  request.denied    request.cancelled
computer.created  computer.updated  computer.deleted
user.created      user.updated      user.deleted      user.password_reset
user.sessions_revoked
token.created     token.revoked
webhook.created   webhook.updated   webhook.deleted
```

## Webhooks

Off unless `WEBHOOKS_ENABLED=true`.

| Method | Path | Scope |
|---|---|---|
| GET | `/webhooks` | `admin` |
| POST | `/webhooks` | `admin` |
| GET | `/webhooks/{id}` | `admin` |
| PATCH | `/webhooks/{id}` | `admin` |
| DELETE | `/webhooks/{id}` | `admin` |
| POST | `/webhooks/{id}/test` | `admin` |
| GET | `/webhooks/{id}/deliveries` | `admin` |

Subscribe with an events list, or `["*"]` for everything. The URL must be `https`, except to
loopback for local development.

Deliveries are signed. `X-Crypt-Signature` is `sha256=` followed by the hex HMAC-SHA256, over
the `X-Crypt-Timestamp` value, a literal `.`, and the raw body, keyed with the secret returned
when the subscription was created. Verify the timestamp is recent to reject replays.

A payload carries identifiers only. Secrets are never delivered to a webhook.

## Maintenance

| Method | Path | Scope |
|---|---|---|
| POST | `/maintenance/cleanup-requests` | `admin` |

Runs the retention sweep on demand. The same sweep runs hourly.

## Deliberate omissions

Fixture export and import stay command-line operations (`cryptctl`, `-import-fixture`). A dump
containing every escrowed secret should not have an HTTP endpoint at all.

Re-encrypting under a new key is likewise a command-line operation (`-rekey`), because the
replacement key would otherwise have to travel over HTTP.

## Security rules the implementation holds to

Plaintext leaves the server through three paths only: `POST /requests/{id}/retrieve`,
`GET /secrets/{id}/value`, and the existing HTML `/retrieve/`. The first two write their audit
event before the response body, so a read is never served without its trail.

Both are rate limited per caller, so a credential valid for one secret cannot drain the
database in a loop faster than anyone reads the audit log.

No list endpoint, CSV export, webhook payload or log line carries a secret. A device token
cannot hold `secrets:reveal` or `secrets:read`, and the server rejects the grant rather than
silently dropping it. A personal access token can never exceed the permissions of the person
who minted it.
