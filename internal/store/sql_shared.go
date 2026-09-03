package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// joinList encodes a string slice for storage in a TEXT column.
func joinList(values []string) string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	return strings.Join(cleaned, ",")
}

// splitList decodes a TEXT column written by joinList.
func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{}
	}
	parts := strings.Split(value, ",")
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	return cleaned
}

// ---------------------------------------------------------------- computers

func updateComputer(db *sql.DB, d dialect, id int, username, computerName string) (*Computer, error) {
	q := newQueryBuilder(d)
	setUsername := q.bind(username)
	setComputerName := q.bind(computerName)
	whereID := q.bind(id)
	query := "UPDATE computers SET username = " + setUsername + ", computername = " + setComputerName +
		" WHERE id = " + whereID + " RETURNING " + computerColumns
	computer, err := scanComputer(db.QueryRow(query, q.args...))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("update computer: %w", err)
	}
	return computer, nil
}

func updateComputerMetadata(db *sql.DB, d dialect, id int, platform, osVersion, agentVersion, hardwareUUID string) error {
	q := newQueryBuilder(d)
	query := "UPDATE computers SET platform = " + q.bind(platform) +
		", os_version = " + q.bind(osVersion) +
		", agent_version = " + q.bind(agentVersion) +
		", hardware_uuid = " + q.bind(hardwareUUID) +
		" WHERE id = " + q.bind(id)
	if _, err := db.Exec(query, q.args...); err != nil {
		return fmt.Errorf("update computer metadata: %w", err)
	}
	return nil
}

// deleteComputer removes a computer and its secrets. Requests referencing those
// secrets are removed first, since the schema protects them from cascade.
func deleteComputer(db *sql.DB, d dialect, id int) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin delete computer: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	deleteRequests := "DELETE FROM requests WHERE secret_id IN (SELECT id FROM secrets WHERE computer_id = " + d.placeholder(1) + ")"
	if _, err := tx.Exec(deleteRequests, id); err != nil {
		return fmt.Errorf("delete computer requests: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM secrets WHERE computer_id = "+d.placeholder(1), id); err != nil {
		return fmt.Errorf("delete computer secrets: %w", err)
	}
	result, err := tx.Exec("DELETE FROM computers WHERE id = "+d.placeholder(1), id)
	if err != nil {
		return fmt.Errorf("delete computer: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete computer rows: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete computer: %w", err)
	}
	return nil
}

func countPendingRequestsForComputer(db *sql.DB, d dialect, computerID int) ([]int, error) {
	query := "SELECT requests.id FROM requests JOIN secrets ON secrets.id = requests.secret_id" +
		" WHERE secrets.computer_id = " + d.placeholder(1) + " AND requests.approved IS NULL ORDER BY requests.id"
	rows, err := db.Query(query, computerID)
	if err != nil {
		return nil, fmt.Errorf("pending requests for computer: %w", err)
	}
	defer rows.Close()

	ids := make([]int, 0)
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan pending request id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ------------------------------------------------------------------ secrets

func deleteSecret(db *sql.DB, d dialect, id int) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin delete secret: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec("DELETE FROM requests WHERE secret_id = "+d.placeholder(1), id); err != nil {
		return fmt.Errorf("delete secret requests: %w", err)
	}
	result, err := tx.Exec("DELETE FROM secrets WHERE id = "+d.placeholder(1), id)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete secret rows: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete secret: %w", err)
	}
	return nil
}

// rekeySecrets re-encrypts every secret from the current codec into the next
// one. It is used when rotating FIELD_ENCRYPTION_KEY.
func rekeySecrets(db *sql.DB, d dialect, current, next SecretCodec) (int, error) {
	if current == nil || next == nil {
		return 0, ErrMissingCodec
	}
	rows, err := db.Query("SELECT id, secret FROM secrets ORDER BY id")
	if err != nil {
		return 0, fmt.Errorf("rekey list secrets: %w", err)
	}
	type pending struct {
		id         int
		ciphertext string
	}
	items := make([]pending, 0)
	for rows.Next() {
		var item pending
		if err := rows.Scan(&item.id, &item.ciphertext); err != nil {
			rows.Close()
			return 0, fmt.Errorf("rekey scan secret: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("rekey iterate secrets: %w", err)
	}
	rows.Close()

	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin rekey: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	updated := 0
	for _, item := range items {
		plaintext, err := current.Decrypt(item.ciphertext)
		if err != nil {
			return 0, fmt.Errorf("rekey decrypt secret %d: %w", item.id, err)
		}
		reencrypted, err := next.Encrypt(plaintext)
		if err != nil {
			return 0, fmt.Errorf("rekey encrypt secret %d: %w", item.id, err)
		}
		query := "UPDATE secrets SET secret = " + d.placeholder(1) + " WHERE id = " + d.placeholder(2)
		if _, err := tx.Exec(query, reencrypted, item.id); err != nil {
			return 0, fmt.Errorf("rekey update secret %d: %w", item.id, err)
		}
		updated++
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit rekey: %w", err)
	}
	return updated, nil
}

// ----------------------------------------------------------------- requests

func cancelRequest(db *sql.DB, d dialect, id int) error {
	query := "DELETE FROM requests WHERE id = " + d.placeholder(1) + " AND approved IS NULL"
	result, err := db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("cancel request: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("cancel request rows: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------- users

func revokeUserSessions(db *sql.DB, d dialect, id int, at time.Time) error {
	query := "UPDATE users SET sessions_revoked_at = " + d.placeholder(1) + " WHERE id = " + d.placeholder(2)
	result, err := db.Exec(query, at, id)
	if err != nil {
		return fmt.Errorf("revoke user sessions: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke user sessions rows: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func getUserSessionsRevokedAt(db *sql.DB, d dialect, username string) (*time.Time, error) {
	query := "SELECT sessions_revoked_at FROM users WHERE username = " + d.placeholder(1)
	var revokedAt sql.NullTime
	if err := db.QueryRow(query, username).Scan(&revokedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get sessions revoked at: %w", err)
	}
	if !revokedAt.Valid {
		return nil, nil
	}
	value := revokedAt.Time
	return &value, nil
}

// ------------------------------------------------------------------- tokens

const tokenColumns = "id, name, prefix, token_hash, kind, scopes, username, created_by, created_at, expires_at, last_used_at, last_used_ip, revoked_at"

func scanAPIToken(row rowScanner) (*APIToken, error) {
	var token APIToken
	var scopes string
	var username sql.NullString
	var lastUsedIP sql.NullString
	var expiresAt, lastUsedAt, revokedAt sql.NullTime
	err := row.Scan(
		&token.ID,
		&token.Name,
		&token.Prefix,
		&token.TokenHash,
		&token.Kind,
		&scopes,
		&username,
		&token.CreatedBy,
		&token.CreatedAt,
		&expiresAt,
		&lastUsedAt,
		&lastUsedIP,
		&revokedAt,
	)
	if err != nil {
		return nil, err
	}
	token.Scopes = splitList(scopes)
	if username.Valid {
		token.Username = username.String
	}
	if lastUsedIP.Valid {
		token.LastUsedIP = lastUsedIP.String
	}
	if expiresAt.Valid {
		value := expiresAt.Time
		token.ExpiresAt = &value
	}
	if lastUsedAt.Valid {
		value := lastUsedAt.Time
		token.LastUsedAt = &value
	}
	if revokedAt.Valid {
		value := revokedAt.Time
		token.RevokedAt = &value
	}
	return &token, nil
}

func addAPIToken(db *sql.DB, d dialect, token APIToken) (*APIToken, error) {
	q := newQueryBuilder(d)
	query := "INSERT INTO api_tokens (name, prefix, token_hash, kind, scopes, username, created_by, created_at, expires_at) VALUES (" +
		q.bind(token.Name) + ", " +
		q.bind(token.Prefix) + ", " +
		q.bind(token.TokenHash) + ", " +
		q.bind(token.Kind) + ", " +
		q.bind(joinList(token.Scopes)) + ", " +
		q.bind(nullableString(token.Username)) + ", " +
		q.bind(token.CreatedBy) + ", " +
		q.bind(token.CreatedAt) + ", " +
		q.bind(nullableTime(token.ExpiresAt)) + ") RETURNING " + tokenColumns
	created, err := scanAPIToken(db.QueryRow(query, q.args...))
	if err != nil {
		return nil, fmt.Errorf("insert api token: %w", err)
	}
	return created, nil
}

func getAPITokenByPrefix(db *sql.DB, d dialect, prefix string) (*APIToken, error) {
	query := "SELECT " + tokenColumns + " FROM api_tokens WHERE prefix = " + d.placeholder(1)
	token, err := scanAPIToken(db.QueryRow(query, prefix))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get api token by prefix: %w", err)
	}
	return token, nil
}

func getAPITokenByID(db *sql.DB, d dialect, id int) (*APIToken, error) {
	query := "SELECT " + tokenColumns + " FROM api_tokens WHERE id = " + d.placeholder(1)
	token, err := scanAPIToken(db.QueryRow(query, id))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get api token by id: %w", err)
	}
	return token, nil
}

func listAPITokens(db *sql.DB) ([]*APIToken, error) {
	rows, err := db.Query("SELECT " + tokenColumns + " FROM api_tokens ORDER BY id")
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()

	tokens := make([]*APIToken, 0)
	for rows.Next() {
		token, err := scanAPIToken(rows)
		if err != nil {
			return nil, fmt.Errorf("scan api token: %w", err)
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func revokeAPIToken(db *sql.DB, d dialect, id int, at time.Time) error {
	query := "UPDATE api_tokens SET revoked_at = " + d.placeholder(1) +
		" WHERE id = " + d.placeholder(2) + " AND revoked_at IS NULL"
	result, err := db.Exec(query, at, id)
	if err != nil {
		return fmt.Errorf("revoke api token: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke api token rows: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func touchAPIToken(db *sql.DB, d dialect, id int, at time.Time, ip string) error {
	query := "UPDATE api_tokens SET last_used_at = " + d.placeholder(1) +
		", last_used_ip = " + d.placeholder(2) + " WHERE id = " + d.placeholder(3)
	if _, err := db.Exec(query, at, nullableString(ip), id); err != nil {
		return fmt.Errorf("touch api token: %w", err)
	}
	return nil
}

// ----------------------------------------------------------------- webhooks

const webhookColumns = "id, url, events, secret, active, created_by, created_at"

func scanWebhook(row rowScanner) (*Webhook, error) {
	var webhook Webhook
	var events string
	if err := row.Scan(&webhook.ID, &webhook.URL, &events, &webhook.Secret, &webhook.Active, &webhook.CreatedBy, &webhook.CreatedAt); err != nil {
		return nil, err
	}
	webhook.Events = splitList(events)
	return &webhook, nil
}

func addWebhook(db *sql.DB, d dialect, webhook Webhook) (*Webhook, error) {
	q := newQueryBuilder(d)
	query := "INSERT INTO webhooks (url, events, secret, active, created_by, created_at) VALUES (" +
		q.bind(webhook.URL) + ", " +
		q.bind(joinList(webhook.Events)) + ", " +
		q.bind(webhook.Secret) + ", " +
		q.bind(webhook.Active) + ", " +
		q.bind(webhook.CreatedBy) + ", " +
		q.bind(webhook.CreatedAt) + ") RETURNING " + webhookColumns
	created, err := scanWebhook(db.QueryRow(query, q.args...))
	if err != nil {
		return nil, fmt.Errorf("insert webhook: %w", err)
	}
	return created, nil
}

func listWebhooks(db *sql.DB) ([]*Webhook, error) {
	rows, err := db.Query("SELECT " + webhookColumns + " FROM webhooks ORDER BY id")
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	defer rows.Close()

	webhooks := make([]*Webhook, 0)
	for rows.Next() {
		webhook, err := scanWebhook(rows)
		if err != nil {
			return nil, fmt.Errorf("scan webhook: %w", err)
		}
		webhooks = append(webhooks, webhook)
	}
	return webhooks, rows.Err()
}

func getWebhook(db *sql.DB, d dialect, id int) (*Webhook, error) {
	query := "SELECT " + webhookColumns + " FROM webhooks WHERE id = " + d.placeholder(1)
	webhook, err := scanWebhook(db.QueryRow(query, id))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get webhook: %w", err)
	}
	return webhook, nil
}

func updateWebhook(db *sql.DB, d dialect, id int, url string, events []string, active bool) (*Webhook, error) {
	q := newQueryBuilder(d)
	query := "UPDATE webhooks SET url = " + q.bind(url) +
		", events = " + q.bind(joinList(events)) +
		", active = " + q.bind(active) +
		" WHERE id = " + q.bind(id) + " RETURNING " + webhookColumns
	webhook, err := scanWebhook(db.QueryRow(query, q.args...))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("update webhook: %w", err)
	}
	return webhook, nil
}

func deleteWebhook(db *sql.DB, d dialect, id int) error {
	result, err := db.Exec("DELETE FROM webhooks WHERE id = "+d.placeholder(1), id)
	if err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete webhook rows: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func addWebhookDelivery(db *sql.DB, d dialect, delivery WebhookDelivery) (*WebhookDelivery, error) {
	q := newQueryBuilder(d)
	query := "INSERT INTO webhook_deliveries (webhook_id, event, payload, status_code, error, attempts, delivered_at) VALUES (" +
		q.bind(delivery.WebhookID) + ", " +
		q.bind(delivery.Event) + ", " +
		q.bind(delivery.Payload) + ", " +
		q.bind(delivery.StatusCode) + ", " +
		q.bind(nullableString(delivery.Error)) + ", " +
		q.bind(delivery.Attempts) + ", " +
		q.bind(delivery.DeliveredAt) + ") RETURNING id"
	var id int
	if err := db.QueryRow(query, q.args...).Scan(&id); err != nil {
		return nil, fmt.Errorf("insert webhook delivery: %w", err)
	}
	delivery.ID = id
	return &delivery, nil
}

func listWebhookDeliveries(db *sql.DB, d dialect, webhookID, limit int) ([]*WebhookDelivery, error) {
	q := newQueryBuilder(d)
	query := "SELECT id, webhook_id, event, payload, status_code, error, attempts, delivered_at FROM webhook_deliveries WHERE webhook_id = " +
		q.bind(webhookID) + " ORDER BY id DESC LIMIT " + q.bind(limit)
	rows, err := db.Query(query, q.args...)
	if err != nil {
		return nil, fmt.Errorf("list webhook deliveries: %w", err)
	}
	defer rows.Close()

	deliveries := make([]*WebhookDelivery, 0)
	for rows.Next() {
		var delivery WebhookDelivery
		var deliveryError sql.NullString
		if err := rows.Scan(&delivery.ID, &delivery.WebhookID, &delivery.Event, &delivery.Payload, &delivery.StatusCode, &deliveryError, &delivery.Attempts, &delivery.DeliveredAt); err != nil {
			return nil, fmt.Errorf("scan webhook delivery: %w", err)
		}
		if deliveryError.Valid {
			delivery.Error = deliveryError.String
		}
		deliveries = append(deliveries, &delivery)
	}
	return deliveries, rows.Err()
}

// -------------------------------------------------------------------- audit

func addAuditEventDetailed(db *sql.DB, d dialect, event AuditEvent) (*AuditEvent, error) {
	q := newQueryBuilder(d)
	query := "INSERT INTO audit_events (actor, target_user, action, reason, ip_address, created_at, target_type, target_id, metadata) VALUES (" +
		q.bind(event.Actor) + ", " +
		q.bind(event.TargetUser) + ", " +
		q.bind(event.Action) + ", " +
		q.bind(nullableString(event.Reason)) + ", " +
		q.bind(nullableString(event.IPAddress)) + ", " +
		q.bind(event.CreatedAt) + ", " +
		q.bind(event.TargetType) + ", " +
		q.bind(event.TargetID) + ", " +
		q.bind(event.Metadata) + ") RETURNING " + auditColumns
	var created AuditEvent
	var reason, ipAddress sql.NullString
	err := db.QueryRow(query, q.args...).Scan(
		&created.ID,
		&created.Actor,
		&created.TargetUser,
		&created.Action,
		&reason,
		&ipAddress,
		&created.CreatedAt,
		&created.TargetType,
		&created.TargetID,
		&created.Metadata,
	)
	if err != nil {
		return nil, fmt.Errorf("insert audit event: %w", err)
	}
	if reason.Valid {
		created.Reason = reason.String
	}
	if ipAddress.Valid {
		created.IPAddress = ipAddress.String
	}
	return &created, nil
}

// -------------------------------------------------------------------- stats

func computeStats(db *sql.DB, d dialect, now time.Time, staleAfter time.Duration) (*Stats, error) {
	stats := &Stats{EscrowedByType: map[string]int{}}

	scalar := func(query string, args ...any) (int, error) {
		var value int
		if err := db.QueryRow(query, args...).Scan(&value); err != nil {
			return 0, err
		}
		return value, nil
	}

	var err error
	if stats.ComputersTotal, err = scalar("SELECT COUNT(*) FROM computers"); err != nil {
		return nil, fmt.Errorf("stats computers total: %w", err)
	}
	if stats.SecretsTotal, err = scalar("SELECT COUNT(*) FROM secrets"); err != nil {
		return nil, fmt.Errorf("stats secrets total: %w", err)
	}
	if stats.UsersTotal, err = scalar("SELECT COUNT(*) FROM users"); err != nil {
		return nil, fmt.Errorf("stats users total: %w", err)
	}
	if stats.PendingRequests, err = scalar("SELECT COUNT(*) FROM requests WHERE approved IS NULL"); err != nil {
		return nil, fmt.Errorf("stats pending requests: %w", err)
	}
	if stats.RotationsPending, err = scalar("SELECT COUNT(*) FROM secrets WHERE rotation_required = "+d.placeholder(1), true); err != nil {
		return nil, fmt.Errorf("stats rotations pending: %w", err)
	}

	windows := []struct {
		target *int
		since  time.Duration
	}{
		{&stats.CheckedIn24h, 24 * time.Hour},
		{&stats.CheckedIn7d, 7 * 24 * time.Hour},
		{&stats.CheckedIn30d, 30 * 24 * time.Hour},
	}
	for _, window := range windows {
		value, err := scalar("SELECT COUNT(*) FROM computers WHERE last_checkin >= "+d.placeholder(1), now.Add(-window.since))
		if err != nil {
			return nil, fmt.Errorf("stats checkin window: %w", err)
		}
		*window.target = value
	}

	if stats.Stale, err = scalar("SELECT COUNT(*) FROM computers WHERE last_checkin IS NULL OR last_checkin < "+d.placeholder(1), now.Add(-staleAfter)); err != nil {
		return nil, fmt.Errorf("stats stale: %w", err)
	}
	if stats.NeverEscrowed, err = scalar("SELECT COUNT(*) FROM computers WHERE NOT EXISTS (SELECT 1 FROM secrets WHERE secrets.computer_id = computers.id)"); err != nil {
		return nil, fmt.Errorf("stats never escrowed: %w", err)
	}

	rows, err := db.Query("SELECT secret_type, COUNT(DISTINCT computer_id) FROM secrets GROUP BY secret_type")
	if err != nil {
		return nil, fmt.Errorf("stats escrowed by type: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var secretType string
		var count int
		if err := rows.Scan(&secretType, &count); err != nil {
			return nil, fmt.Errorf("scan stats escrowed by type: %w", err)
		}
		stats.EscrowedByType[secretType] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate stats escrowed by type: %w", err)
	}
	return stats, nil
}

// nullableTime maps a nil pointer onto SQL NULL.
func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return *value
}
