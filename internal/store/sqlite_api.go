package store

import "time"

// API surface methods for the SQLite store. The queries themselves live in
// sql_shared.go and sql_dialect.go so both backends stay in step.

func (s *SQLiteStore) ListComputersFiltered(filter ComputerFilter) ([]*Computer, error) {
	return listComputersFiltered(s.db, sqliteDialect, filter)
}

func (s *SQLiteStore) CountComputersFiltered(filter ComputerFilter) (int, error) {
	return countComputersFiltered(s.db, sqliteDialect, filter)
}

func (s *SQLiteStore) UpdateComputer(id int, username, computerName string) (*Computer, error) {
	return updateComputer(s.db, sqliteDialect, id, username, computerName)
}

func (s *SQLiteStore) UpdateComputerMetadata(id int, platform, osVersion, agentVersion, hardwareUUID string) error {
	return updateComputerMetadata(s.db, sqliteDialect, id, platform, osVersion, agentVersion, hardwareUUID)
}

func (s *SQLiteStore) DeleteComputer(id int) error {
	return deleteComputer(s.db, sqliteDialect, id)
}

func (s *SQLiteStore) PendingRequestIDsForComputer(computerID int) ([]int, error) {
	return countPendingRequestsForComputer(s.db, sqliteDialect, computerID)
}

func (s *SQLiteStore) ListSecretsFiltered(filter SecretFilter) ([]*Secret, error) {
	return listSecretsFiltered(s.db, sqliteDialect, s.codec, filter)
}

func (s *SQLiteStore) CountSecretsFiltered(filter SecretFilter) (int, error) {
	return countSecretsFiltered(s.db, sqliteDialect, filter)
}

func (s *SQLiteStore) DeleteSecret(id int) error {
	return deleteSecret(s.db, sqliteDialect, id)
}

func (s *SQLiteStore) RekeySecrets(next SecretCodec) (int, error) {
	return rekeySecrets(s.db, sqliteDialect, s.codec, next)
}

func (s *SQLiteStore) ListRequestsFiltered(filter RequestFilter) ([]*Request, error) {
	return listRequestsFiltered(s.db, sqliteDialect, filter)
}

func (s *SQLiteStore) CountRequestsFiltered(filter RequestFilter) (int, error) {
	return countRequestsFiltered(s.db, sqliteDialect, filter)
}

func (s *SQLiteStore) CancelRequest(id int) error {
	return cancelRequest(s.db, sqliteDialect, id)
}

func (s *SQLiteStore) ListUsersFiltered(filter UserFilter) ([]*User, error) {
	return listUsersFiltered(s.db, sqliteDialect, filter)
}

func (s *SQLiteStore) CountUsersFiltered(filter UserFilter) (int, error) {
	return countUsersFiltered(s.db, sqliteDialect, filter)
}

func (s *SQLiteStore) RevokeUserSessions(id int, at time.Time) error {
	return revokeUserSessions(s.db, sqliteDialect, id, at)
}

func (s *SQLiteStore) SessionsRevokedAt(username string) (*time.Time, error) {
	return getUserSessionsRevokedAt(s.db, sqliteDialect, username)
}

func (s *SQLiteStore) AddAPIToken(token APIToken) (*APIToken, error) {
	return addAPIToken(s.db, sqliteDialect, token)
}

func (s *SQLiteStore) GetAPITokenByPrefix(prefix string) (*APIToken, error) {
	return getAPITokenByPrefix(s.db, sqliteDialect, prefix)
}

func (s *SQLiteStore) GetAPITokenByID(id int) (*APIToken, error) {
	return getAPITokenByID(s.db, sqliteDialect, id)
}

func (s *SQLiteStore) ListAPITokens() ([]*APIToken, error) {
	return listAPITokens(s.db)
}

func (s *SQLiteStore) RevokeAPIToken(id int, at time.Time) error {
	return revokeAPIToken(s.db, sqliteDialect, id, at)
}

func (s *SQLiteStore) TouchAPIToken(id int, at time.Time, ip string) error {
	return touchAPIToken(s.db, sqliteDialect, id, at, ip)
}

func (s *SQLiteStore) AddWebhook(webhook Webhook) (*Webhook, error) {
	return addWebhook(s.db, sqliteDialect, webhook)
}

func (s *SQLiteStore) ListWebhooks() ([]*Webhook, error) {
	return listWebhooks(s.db)
}

func (s *SQLiteStore) GetWebhook(id int) (*Webhook, error) {
	return getWebhook(s.db, sqliteDialect, id)
}

func (s *SQLiteStore) UpdateWebhook(id int, url string, events []string, active bool) (*Webhook, error) {
	return updateWebhook(s.db, sqliteDialect, id, url, events, active)
}

func (s *SQLiteStore) DeleteWebhook(id int) error {
	return deleteWebhook(s.db, sqliteDialect, id)
}

func (s *SQLiteStore) AddWebhookDelivery(delivery WebhookDelivery) (*WebhookDelivery, error) {
	return addWebhookDelivery(s.db, sqliteDialect, delivery)
}

func (s *SQLiteStore) ListWebhookDeliveries(webhookID, limit int) ([]*WebhookDelivery, error) {
	return listWebhookDeliveries(s.db, sqliteDialect, webhookID, limit)
}

func (s *SQLiteStore) AddAuditEventDetailed(event AuditEvent) (*AuditEvent, error) {
	return addAuditEventDetailed(s.db, sqliteDialect, event)
}

func (s *SQLiteStore) ListAuditEventsFiltered(filter AuditFilter) ([]*AuditEvent, error) {
	return listAuditEventsFiltered(s.db, sqliteDialect, filter)
}

func (s *SQLiteStore) CountAuditEventsFiltered(filter AuditFilter) (int, error) {
	return countAuditEventsFiltered(s.db, sqliteDialect, filter)
}

func (s *SQLiteStore) Stats(now time.Time, staleAfter time.Duration) (*Stats, error) {
	return computeStats(s.db, sqliteDialect, now, staleAfter)
}
