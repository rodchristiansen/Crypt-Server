package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// dialect captures the small number of SQL differences between the sqlite and
// postgres backends so that filtered queries can be written once.
type dialect struct {
	name string
}

var (
	sqliteDialect   = dialect{name: "sqlite"}
	postgresDialect = dialect{name: "postgres"}
)

// placeholder renders the bind marker for the n-th argument (1-indexed).
func (d dialect) placeholder(n int) string {
	if d.name == "postgres" {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

// likeOperator returns the case-insensitive LIKE operator for the dialect.
// SQLite's LIKE is already case-insensitive for ASCII.
func (d dialect) likeOperator() string {
	if d.name == "postgres" {
		return "ILIKE"
	}
	return "LIKE"
}

// queryBuilder accumulates bind arguments and renders dialect-correct
// placeholders as clauses are appended.
type queryBuilder struct {
	dialect dialect
	args    []any
}

func newQueryBuilder(d dialect) *queryBuilder {
	return &queryBuilder{dialect: d}
}

// bind records a value and returns the placeholder that refers to it.
func (q *queryBuilder) bind(value any) string {
	q.args = append(q.args, value)
	return q.dialect.placeholder(len(q.args))
}

// like records a search term wrapped in wildcards and returns the full
// comparison fragment for the given column.
func (q *queryBuilder) like(column, term string) string {
	return fmt.Sprintf("%s %s %s", column, q.dialect.likeOperator(), q.bind("%"+term+"%"))
}

const computerColumns = "id, serial, username, computername, last_checkin, platform, os_version, agent_version, hardware_uuid"

type rowScanner interface {
	Scan(dest ...any) error
}

func scanComputer(row rowScanner) (*Computer, error) {
	var computer Computer
	var lastCheckin sql.NullTime
	err := row.Scan(
		&computer.ID,
		&computer.Serial,
		&computer.Username,
		&computer.ComputerName,
		&lastCheckin,
		&computer.Platform,
		&computer.OSVersion,
		&computer.AgentVersion,
		&computer.HardwareUUID,
	)
	if err != nil {
		return nil, err
	}
	if lastCheckin.Valid {
		computer.LastCheckin = lastCheckin.Time
	}
	return &computer, nil
}

func scanComputers(rows *sql.Rows) ([]*Computer, error) {
	computers := make([]*Computer, 0)
	for rows.Next() {
		computer, err := scanComputer(rows)
		if err != nil {
			return nil, fmt.Errorf("scan computer: %w", err)
		}
		computers = append(computers, computer)
	}
	return computers, rows.Err()
}

// ComputerFilter narrows a computer listing. Zero values mean "no constraint".
type ComputerFilter struct {
	Search           string
	Username         string
	Platform         string
	SecretType       string
	Escrowed         *bool
	RotationRequired *bool
	CheckedInBefore  *time.Time
	CheckedInAfter   *time.Time
	Sort             string
	Limit            int
	Offset           int
}

// where renders the shared WHERE clause for a computer filter.
func (f ComputerFilter) where(q *queryBuilder) string {
	clauses := make([]string, 0)
	if f.Search != "" {
		clauses = append(clauses, "("+
			q.like("serial", f.Search)+" OR "+
			q.like("computername", f.Search)+" OR "+
			q.like("username", f.Search)+")")
	}
	if f.Username != "" {
		clauses = append(clauses, q.like("username", f.Username))
	}
	if f.Platform != "" {
		clauses = append(clauses, "platform = "+q.bind(f.Platform))
	}
	if f.CheckedInAfter != nil {
		clauses = append(clauses, "last_checkin >= "+q.bind(*f.CheckedInAfter))
	}
	if f.CheckedInBefore != nil {
		clauses = append(clauses, "last_checkin < "+q.bind(*f.CheckedInBefore))
	}
	if f.Escrowed != nil || f.SecretType != "" || f.RotationRequired != nil {
		sub := "SELECT 1 FROM secrets WHERE secrets.computer_id = computers.id"
		if f.SecretType != "" {
			sub += " AND secrets.secret_type = " + q.bind(f.SecretType)
		}
		if f.RotationRequired != nil {
			sub += " AND secrets.rotation_required = " + q.bind(*f.RotationRequired)
		}
		if f.Escrowed != nil && !*f.Escrowed {
			clauses = append(clauses, "NOT EXISTS ("+sub+")")
		} else {
			clauses = append(clauses, "EXISTS ("+sub+")")
		}
	}
	if len(clauses) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(clauses, " AND ")
}

// orderBy renders a safe ORDER BY clause. Unknown sort keys fall back to id.
func (f ComputerFilter) orderBy() string {
	direction := " ASC"
	key := f.Sort
	if strings.HasPrefix(key, "-") {
		key = strings.TrimPrefix(key, "-")
		direction = " DESC"
	}
	switch key {
	case "serial":
		return " ORDER BY serial" + direction
	case "username":
		return " ORDER BY username" + direction
	case "computername", "computer_name":
		return " ORDER BY computername" + direction
	case "last_checkin":
		return " ORDER BY last_checkin" + direction + ", id" + direction
	default:
		return " ORDER BY id" + direction
	}
}

func (f ComputerFilter) limitOffset(q *queryBuilder) string {
	if f.Limit <= 0 {
		return ""
	}
	return " LIMIT " + q.bind(f.Limit) + " OFFSET " + q.bind(f.Offset)
}

func listComputersFiltered(db *sql.DB, d dialect, filter ComputerFilter) ([]*Computer, error) {
	q := newQueryBuilder(d)
	query := "SELECT " + computerColumns + " FROM computers" + filter.where(q) + filter.orderBy() + filter.limitOffset(q)
	rows, err := db.Query(query, q.args...)
	if err != nil {
		return nil, fmt.Errorf("list computers filtered: %w", err)
	}
	defer rows.Close()
	return scanComputers(rows)
}

func countComputersFiltered(db *sql.DB, d dialect, filter ComputerFilter) (int, error) {
	q := newQueryBuilder(d)
	query := "SELECT COUNT(*) FROM computers" + filter.where(q)
	var count int
	if err := db.QueryRow(query, q.args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count computers filtered: %w", err)
	}
	return count, nil
}

// SecretFilter narrows a secret listing.
type SecretFilter struct {
	ComputerID       int
	SecretType       string
	RotationRequired *bool
	EscrowedBefore   *time.Time
	EscrowedAfter    *time.Time
	Limit            int
	Offset           int
}

func (f SecretFilter) where(q *queryBuilder) string {
	clauses := make([]string, 0)
	if f.ComputerID > 0 {
		clauses = append(clauses, "computer_id = "+q.bind(f.ComputerID))
	}
	if f.SecretType != "" {
		clauses = append(clauses, "secret_type = "+q.bind(f.SecretType))
	}
	if f.RotationRequired != nil {
		clauses = append(clauses, "rotation_required = "+q.bind(*f.RotationRequired))
	}
	if f.EscrowedAfter != nil {
		clauses = append(clauses, "date_escrowed >= "+q.bind(*f.EscrowedAfter))
	}
	if f.EscrowedBefore != nil {
		clauses = append(clauses, "date_escrowed < "+q.bind(*f.EscrowedBefore))
	}
	if len(clauses) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(clauses, " AND ")
}

func listSecretsFiltered(db *sql.DB, d dialect, codec SecretCodec, filter SecretFilter) ([]*Secret, error) {
	if codec == nil {
		return nil, ErrMissingCodec
	}
	q := newQueryBuilder(d)
	query := "SELECT id, computer_id, secret, secret_type, date_escrowed, rotation_required FROM secrets" +
		filter.where(q) + " ORDER BY id DESC"
	if filter.Limit > 0 {
		query += " LIMIT " + q.bind(filter.Limit) + " OFFSET " + q.bind(filter.Offset)
	}
	rows, err := db.Query(query, q.args...)
	if err != nil {
		return nil, fmt.Errorf("list secrets filtered: %w", err)
	}
	defer rows.Close()

	secrets := make([]*Secret, 0)
	for rows.Next() {
		var secret Secret
		var encrypted string
		if err := rows.Scan(&secret.ID, &secret.ComputerID, &encrypted, &secret.SecretType, &secret.DateEscrowed, &secret.RotationRequired); err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		plaintext, err := codec.Decrypt(encrypted)
		if err != nil {
			return nil, fmt.Errorf("decrypt secret: %w", err)
		}
		secret.Secret = plaintext
		secrets = append(secrets, &secret)
	}
	return secrets, rows.Err()
}

func countSecretsFiltered(db *sql.DB, d dialect, filter SecretFilter) (int, error) {
	q := newQueryBuilder(d)
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM secrets"+filter.where(q), q.args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count secrets filtered: %w", err)
	}
	return count, nil
}

// RequestFilter narrows a request listing. Status is one of pending, approved
// or denied; an empty status matches every request.
type RequestFilter struct {
	Status         string
	SecretID       int
	ComputerSerial string
	RequestingUser string
	CurrentOnly    bool
	Limit          int
	Offset         int
}

func (f RequestFilter) where(q *queryBuilder) string {
	clauses := make([]string, 0)
	switch f.Status {
	case "pending":
		clauses = append(clauses, "requests.approved IS NULL")
	case "approved":
		clauses = append(clauses, "requests.approved = "+q.bind(true))
	case "denied":
		clauses = append(clauses, "requests.approved = "+q.bind(false))
	}
	if f.SecretID > 0 {
		clauses = append(clauses, "requests.secret_id = "+q.bind(f.SecretID))
	}
	if f.RequestingUser != "" {
		clauses = append(clauses, "requests.requesting_user = "+q.bind(f.RequestingUser))
	}
	if f.CurrentOnly {
		clauses = append(clauses, "requests.current = "+q.bind(true))
	}
	if f.ComputerSerial != "" {
		clauses = append(clauses, "requests.secret_id IN (SELECT secrets.id FROM secrets JOIN computers ON computers.id = secrets.computer_id WHERE "+
			q.like("computers.serial", f.ComputerSerial)+")")
	}
	if len(clauses) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(clauses, " AND ")
}

const requestColumns = "requests.id, requests.secret_id, requests.requesting_user, requests.approved, requests.auth_user, requests.reason_for_request, requests.reason_for_approval, requests.date_requested, requests.date_approved, requests.current"

func scanRequestRows(rows *sql.Rows) ([]*Request, error) {
	requests := make([]*Request, 0)
	for rows.Next() {
		var request Request
		var approved sql.NullBool
		var authUser sql.NullString
		var reasonForApproval sql.NullString
		var dateApproved sql.NullTime
		if err := rows.Scan(
			&request.ID,
			&request.SecretID,
			&request.RequestingUser,
			&approved,
			&authUser,
			&request.ReasonForRequest,
			&reasonForApproval,
			&request.DateRequested,
			&dateApproved,
			&request.Current,
		); err != nil {
			return nil, fmt.Errorf("scan request: %w", err)
		}
		if approved.Valid {
			value := approved.Bool
			request.Approved = &value
		}
		if authUser.Valid {
			request.AuthUser = authUser.String
		}
		if reasonForApproval.Valid {
			request.ReasonForApproval = reasonForApproval.String
		}
		if dateApproved.Valid {
			value := dateApproved.Time
			request.DateApproved = &value
		}
		requests = append(requests, &request)
	}
	return requests, rows.Err()
}

func listRequestsFiltered(db *sql.DB, d dialect, filter RequestFilter) ([]*Request, error) {
	q := newQueryBuilder(d)
	query := "SELECT " + requestColumns + " FROM requests" + filter.where(q) + " ORDER BY requests.id DESC"
	if filter.Limit > 0 {
		query += " LIMIT " + q.bind(filter.Limit) + " OFFSET " + q.bind(filter.Offset)
	}
	rows, err := db.Query(query, q.args...)
	if err != nil {
		return nil, fmt.Errorf("list requests filtered: %w", err)
	}
	defer rows.Close()
	return scanRequestRows(rows)
}

func countRequestsFiltered(db *sql.DB, d dialect, filter RequestFilter) (int, error) {
	q := newQueryBuilder(d)
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM requests"+filter.where(q), q.args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count requests filtered: %w", err)
	}
	return count, nil
}

// UserFilter narrows a user listing.
type UserFilter struct {
	Search     string
	AuthSource string
	IsStaff    *bool
	CanApprove *bool
	Limit      int
	Offset     int
}

func (f UserFilter) where(q *queryBuilder) string {
	clauses := make([]string, 0)
	if f.Search != "" {
		clauses = append(clauses, q.like("username", f.Search))
	}
	if f.AuthSource != "" {
		clauses = append(clauses, "auth_source = "+q.bind(f.AuthSource))
	}
	if f.IsStaff != nil {
		clauses = append(clauses, "is_staff = "+q.bind(*f.IsStaff))
	}
	if f.CanApprove != nil {
		clauses = append(clauses, "can_approve = "+q.bind(*f.CanApprove))
	}
	if len(clauses) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(clauses, " AND ")
}

func listUsersFiltered(db *sql.DB, d dialect, filter UserFilter) ([]*User, error) {
	q := newQueryBuilder(d)
	query := "SELECT id, username, password_hash, is_staff, can_approve, local_login_enabled, must_reset_password, auth_source FROM users" +
		filter.where(q) + " ORDER BY username"
	if filter.Limit > 0 {
		query += " LIMIT " + q.bind(filter.Limit) + " OFFSET " + q.bind(filter.Offset)
	}
	rows, err := db.Query(query, q.args...)
	if err != nil {
		return nil, fmt.Errorf("list users filtered: %w", err)
	}
	defer rows.Close()

	users := make([]*User, 0)
	for rows.Next() {
		var user User
		var passwordHash sql.NullString
		if err := rows.Scan(&user.ID, &user.Username, &passwordHash, &user.IsStaff, &user.CanApprove, &user.LocalLoginEnabled, &user.MustResetPassword, &user.AuthSource); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		if passwordHash.Valid {
			user.PasswordHash = passwordHash.String
		}
		users = append(users, &user)
	}
	return users, rows.Err()
}

func countUsersFiltered(db *sql.DB, d dialect, filter UserFilter) (int, error) {
	q := newQueryBuilder(d)
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM users"+filter.where(q), q.args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count users filtered: %w", err)
	}
	return count, nil
}

// AuditFilter narrows an audit event listing.
type AuditFilter struct {
	Search     string
	Actor      string
	Action     string
	TargetUser string
	TargetType string
	From       *time.Time
	To         *time.Time
	Limit      int
	Offset     int
}

func (f AuditFilter) where(q *queryBuilder) string {
	clauses := make([]string, 0)
	if f.Search != "" {
		clauses = append(clauses, "("+
			q.like("actor", f.Search)+" OR "+
			q.like("target_user", f.Search)+" OR "+
			q.like("action", f.Search)+" OR "+
			q.like("COALESCE(reason, '')", f.Search)+" OR "+
			q.like("COALESCE(ip_address, '')", f.Search)+")")
	}
	if f.Actor != "" {
		clauses = append(clauses, "actor = "+q.bind(f.Actor))
	}
	if f.Action != "" {
		clauses = append(clauses, "action = "+q.bind(f.Action))
	}
	if f.TargetUser != "" {
		clauses = append(clauses, "target_user = "+q.bind(f.TargetUser))
	}
	if f.TargetType != "" {
		clauses = append(clauses, "target_type = "+q.bind(f.TargetType))
	}
	if f.From != nil {
		clauses = append(clauses, "created_at >= "+q.bind(*f.From))
	}
	if f.To != nil {
		clauses = append(clauses, "created_at < "+q.bind(*f.To))
	}
	if len(clauses) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(clauses, " AND ")
}

const auditColumns = "id, actor, target_user, action, reason, ip_address, created_at, target_type, target_id, metadata"

func scanAuditEventRows(rows *sql.Rows) ([]*AuditEvent, error) {
	events := make([]*AuditEvent, 0)
	for rows.Next() {
		var event AuditEvent
		var reason sql.NullString
		var ipAddress sql.NullString
		if err := rows.Scan(
			&event.ID,
			&event.Actor,
			&event.TargetUser,
			&event.Action,
			&reason,
			&ipAddress,
			&event.CreatedAt,
			&event.TargetType,
			&event.TargetID,
			&event.Metadata,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		if reason.Valid {
			event.Reason = reason.String
		}
		if ipAddress.Valid {
			event.IPAddress = ipAddress.String
		}
		events = append(events, &event)
	}
	return events, rows.Err()
}

func listAuditEventsFiltered(db *sql.DB, d dialect, filter AuditFilter) ([]*AuditEvent, error) {
	q := newQueryBuilder(d)
	query := "SELECT " + auditColumns + " FROM audit_events" + filter.where(q) + " ORDER BY created_at DESC, id DESC"
	if filter.Limit > 0 {
		query += " LIMIT " + q.bind(filter.Limit) + " OFFSET " + q.bind(filter.Offset)
	}
	rows, err := db.Query(query, q.args...)
	if err != nil {
		return nil, fmt.Errorf("list audit events filtered: %w", err)
	}
	defer rows.Close()
	return scanAuditEventRows(rows)
}

func countAuditEventsFiltered(db *sql.DB, d dialect, filter AuditFilter) (int, error) {
	q := newQueryBuilder(d)
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM audit_events"+filter.where(q), q.args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count audit events filtered: %w", err)
	}
	return count, nil
}
