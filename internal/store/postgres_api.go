package store

import "time"

// API surface methods for the Postgres store. The queries themselves live in
// sql_shared.go and sql_dialect.go so both backends stay in step.

func (s *PostgresStore) ListComputersFiltered(filter ComputerFilter) ([]*Computer, error) {
	return listComputersFiltered(s.db, postgresDialect, filter)
}

func (s *PostgresStore) CountComputersFiltered(filter ComputerFilter) (int, error) {
	return countComputersFiltered(s.db, postgresDialect, filter)
}

func (s *PostgresStore) UpdateComputer(id int, username, computerName string) (*Computer, error) {
	return updateComputer(s.db, postgresDialect, id, username, computerName)
}

func (s *PostgresStore) UpdateComputerMetadata(id int, platform, osVersion, agentVersion, hardwareUUID string) error {
	return updateComputerMetadata(s.db, postgresDialect, id, platform, osVersion, agentVersion, hardwareUUID)
}

func (s *PostgresStore) DeleteComputer(id int) error {
	return deleteComputer(s.db, postgresDialect, id)
}

func (s *PostgresStore) PendingRequestIDsForComputer(computerID int) ([]int, error) {
	return countPendingRequestsForComputer(s.db, postgresDialect, computerID)
}

func (s *PostgresStore) ListSecretsFiltered(filter SecretFilter) ([]*Secret, error) {
	return listSecretsFiltered(s.db, postgresDialect, s.codec, filter)
}

func (s *PostgresStore) CountSecretsFiltered(filter SecretFilter) (int, error) {
	return countSecretsFiltered(s.db, postgresDialect, filter)
}

func (s *PostgresStore) DeleteSecret(id int) error {
	return deleteSecret(s.db, postgresDialect, id)
}

func (s *PostgresStore) RekeySecrets(next SecretCodec) (int, error) {
	return rekeySecrets(s.db, postgresDialect, s.codec, next)
}

func (s *PostgresStore) ListRequestsFiltered(filter RequestFilter) ([]*Request, error) {
	return listRequestsFiltered(s.db, postgresDialect, filter)
}

func (s *PostgresStore) CountRequestsFiltered(filter RequestFilter) (int, error) {
	return countRequestsFiltered(s.db, postgresDialect, filter)
}

func (s *PostgresStore) CancelRequest(id int) error {
	return cancelRequest(s.db, postgresDialect, id)
}

func (s *PostgresStore) ListUsersFiltered(filter UserFilter) ([]*User, error) {
	return listUsersFiltered(s.db, postgresDialect, filter)
}

func (s *PostgresStore) CountUsersFiltered(filter UserFilter) (int, error) {
	return countUsersFiltered(s.db, postgresDialect, filter)
}

func (s *PostgresStore) RevokeUserSessions(id int, at time.Time) error {
	return revokeUserSessions(s.db, postgresDialect, id, at)
}

func (s *PostgresStore) SessionsRevokedAt(username string) (*time.Time, error) {
	return getUserSessionsRevokedAt(s.db, postgresDialect, username)
}

func (s *PostgresStore) AddAPIToken(token APIToken) (*APIToken, error) {
	return addAPIToken(s.db, postgresDialect, token)
}

func (s *PostgresStore) GetAPITokenByPrefix(prefix string) (*APIToken, error) {
	return getAPITokenByPrefix(s.db, postgresDialect, prefix)
}

func (s *PostgresStore) GetAPITokenByID(id int) (*APIToken, error) {
	return getAPITokenByID(s.db, postgresDialect, id)
}

func (s *PostgresStore) ListAPITokens() ([]*APIToken, error) {
	return listAPITokens(s.db)
}

func (s *PostgresStore) RevokeAPIToken(id int, at time.Time) error {
	return revokeAPIToken(s.db, postgresDialect, id, at)
}

func (s *PostgresStore) TouchAPIToken(id int, at time.Time, ip string) error {
	return touchAPIToken(s.db, postgresDialect, id, at, ip)
}

func (s *PostgresStore) AddWebhook(webhook Webhook) (*Webhook, error) {
	return addWebhook(s.db, postgresDialect, webhook)
}

func (s *PostgresStore) ListWebhooks() ([]*Webhook, error) {
	return listWebhooks(s.db)
}

func (s *PostgresStore) GetWebhook(id int) (*Webhook, error) {
	return getWebhook(s.db, postgresDialect, id)
}

func (s *PostgresStore) UpdateWebhook(id int, url string, events []string, active bool) (*Webhook, error) {
	return updateWebhook(s.db, postgresDialect, id, url, events, active)
}

func (s *PostgresStore) DeleteWebhook(id int) error {
	return deleteWebhook(s.db, postgresDialect, id)
}

func (s *PostgresStore) AddWebhookDelivery(delivery WebhookDelivery) (*WebhookDelivery, error) {
	return addWebhookDelivery(s.db, postgresDialect, delivery)
}

func (s *PostgresStore) ListWebhookDeliveries(webhookID, limit int) ([]*WebhookDelivery, error) {
	return listWebhookDeliveries(s.db, postgresDialect, webhookID, limit)
}

func (s *PostgresStore) AddAuditEventDetailed(event AuditEvent) (*AuditEvent, error) {
	return addAuditEventDetailed(s.db, postgresDialect, event)
}

func (s *PostgresStore) ListAuditEventsFiltered(filter AuditFilter) ([]*AuditEvent, error) {
	return listAuditEventsFiltered(s.db, postgresDialect, filter)
}

func (s *PostgresStore) CountAuditEventsFiltered(filter AuditFilter) (int, error) {
	return countAuditEventsFiltered(s.db, postgresDialect, filter)
}

func (s *PostgresStore) Stats(now time.Time, staleAfter time.Duration) (*Stats, error) {
	return computeStats(s.db, postgresDialect, now, staleAfter)
}
