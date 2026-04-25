package internaldb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

var (
	ErrNoSourcesConfigured = errors.New("no internal DB sources configured")
	ErrSourceNotFound      = errors.New("internal DB source not found")
	ErrInvalidQuery        = errors.New("only read-only SELECT/WITH queries are allowed")
	ErrUnsupportedSQL      = errors.New("query contains unsupported SQL keyword")
)

var sourceNameRegexp = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

var forbiddenKeywordRegexp = regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|MERGE|REPLACE|GRANT|REVOKE|CALL|EXEC(?:UTE)?|COPY)\b`)

const (
	defaultRowsLimit   = 200
	maxRowsLimit       = 1000
	maxQueryLength     = 20000
	defaultQueryTimeout = 8 * time.Second
)

type Manager struct {
	sources       map[string]string
	pools         map[string]*sql.DB
	mu            sync.RWMutex
	queryTimeout  time.Duration
	repository    *Repository
	envSourceSpec string
}

func NewManager(repository *Repository, raw string, queryTimeout time.Duration) (*Manager, error) {
	if queryTimeout <= 0 {
		queryTimeout = defaultQueryTimeout
	}

	m := &Manager{
		sources:       make(map[string]string),
		pools:         make(map[string]*sql.DB),
		queryTimeout:  queryTimeout,
		repository:    repository,
		envSourceSpec: raw,
	}

	if err := m.RefreshSources(context.Background()); err != nil {
		return m, err
	}

	return m, nil
}

func (m *Manager) ListSources() []string {
	if m == nil {
		return []string{}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.sources))
	for name := range m.sources {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// IsEnvSource returns true if the source with the given name was loaded from
// env-var config (INTERNAL_DB_SOURCES). Env sources are global/default-org
// and accessible to all tenants regardless of the per-org DB filter.
func (m *Manager) IsEnvSource(name string) bool {
	if m == nil {
		return false
	}
	envSources, _ := parseSourceMap(m.envSourceSpec)
	_, ok := envSources[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func (m *Manager) RefreshSources(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	next, errs := m.collectSources(ctx)
	m.replaceSources(next)

	if len(errs) > 0 {
		return fmt.Errorf("refresh errors: %s", strings.Join(errs, "; "))
	}

	return nil
}

func (m *Manager) Query(ctx context.Context, source, rawQuery string, maxRows int) ([]string, []map[string]interface{}, bool, error) {
	if queryTimeout := m.getQueryTimeout(); queryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, queryTimeout)
		defer cancel()
	}

	if m == nil {
		return nil, nil, false, ErrNoSourcesConfigured
	}

	m.mu.RLock()
	hasSources := len(m.sources) > 0
	m.mu.RUnlock()
	if !hasSources {
		return nil, nil, false, ErrNoSourcesConfigured
	}

	query, limit, err := sanitizeQuery(rawQuery, maxRows)
	if err != nil {
		return nil, nil, false, err
	}

	db, err := m.getDB(ctx, source)
	if err != nil {
		return nil, nil, false, err
	}

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, nil, false, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, nil, false, err
	}

	results := make([]map[string]interface{}, 0)
	truncated := false
	for rows.Next() {
		if len(results) >= limit {
			truncated = true
			break
		}

		values := make([]interface{}, len(columns))
		scanArgs := make([]interface{}, len(columns))
		for i := range values {
			scanArgs[i] = &values[i]
		}
		if err := rows.Scan(scanArgs...); err != nil {
			return nil, nil, false, err
		}

		row := make(map[string]interface{}, len(columns))
		for i, col := range columns {
			row[col] = normalizeRowValue(values[i])
		}
		results = append(results, row)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, false, err
	}

	return columns, results, truncated, nil
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var closeErr error
	for _, db := range m.pools {
		if err := db.Close(); err != nil {
			closeErr = err
		}
	}
	return closeErr
}

func (m *Manager) getDB(ctx context.Context, source string) (*sql.DB, error) {
	if m == nil {
		return nil, ErrNoSourcesConfigured
	}

	name := strings.ToLower(strings.TrimSpace(source))
	if name == "" {
		return nil, ErrSourceNotFound
	}

	m.mu.RLock()
	dsn, found := m.sources[name]
	if found {
		if db, ok := m.pools[name]; ok {
			m.mu.RUnlock()
			if err := db.PingContext(ctx); err == nil {
				return db, nil
			}
			m.mu.Lock()
			_ = db.Close()
			delete(m.pools, name)
			m.mu.Unlock()
			goto create
		}
	}
	m.mu.RUnlock()
	if !found {
		return nil, ErrSourceNotFound
	}

create:
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(15 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	m.mu.Lock()
	m.pools[name] = db
	m.mu.Unlock()
	return db, nil
}

func (m *Manager) collectSources(ctx context.Context) (map[string]string, []string) {
	combined := make(map[string]string)
	var errs []string

	envSources, envErrs := parseSourceMap(m.envSourceSpec)
	if len(envErrs) > 0 {
		errs = append(errs, envErrs...)
	}
	for name, dsn := range envSources {
		combined[name] = dsn
	}

	if m.repository == nil {
		return combined, errs
	}

	dbSources, err := m.repository.ListSources(ctx, "", true) // manager refresh is global (no org filter)
	if err != nil {
		errs = append(errs, err.Error())
		return combined, errs
	}

	for _, source := range dbSources {
		name, err := normalizeSourceName(source.Name)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if _, exists := combined[name]; exists {
			continue
		}
		dsn := strings.TrimSpace(source.DSN)
		if dsn == "" {
			errs = append(errs, fmt.Sprintf("empty DSN for source %s", source.Name))
			continue
		}
		if err := validateDSN(dsn); err != nil {
			errs = append(errs, fmt.Sprintf("invalid DB source %s: %v", source.Name, err))
			continue
		}
		combined[name] = dsn
	}

	return combined, errs
}

func (m *Manager) replaceSources(next map[string]string) {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for name, existing := range m.pools {
		nextDSN, ok := next[name]
		if !ok {
			_ = existing.Close()
			delete(m.pools, name)
			continue
		}
		if current, exists := m.sources[name]; !exists || current != nextDSN {
			_ = existing.Close()
			delete(m.pools, name)
		}
	}

	m.sources = make(map[string]string, len(next))
	for name, dsn := range next {
		m.sources[name] = dsn
	}
}

func (m *Manager) getQueryTimeout() time.Duration {
	if m == nil {
		return defaultQueryTimeout
	}
	return m.queryTimeout
}

func normalizeSourceName(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if !sourceNameRegexp.MatchString(name) {
		return "", fmt.Errorf("invalid source name: %s", raw)
	}
	return name, nil
}

func parseSourceMap(raw string) (map[string]string, []string) {
	out := make(map[string]string)
	var errs []string

	nonEmpty := strings.TrimSpace(raw)
	if nonEmpty == "" {
		return out, nil
	}

	parts := strings.Split(nonEmpty, ",")
	for _, part := range parts {
		name, dsn, parseErr := parseSourceSpec(part)
		if parseErr != nil {
			errs = append(errs, parseErr.Error())
			continue
		}
		if _, exists := out[name]; exists {
			errs = append(errs, fmt.Sprintf("duplicate source %s", name))
			continue
		}
		out[name] = dsn
	}

	return out, errs
}

func parseSourceSpec(raw string) (string, string, error) {
	part := strings.TrimSpace(raw)
	if part == "" {
		return "", "", errors.New("empty source definition")
	}

	kv := strings.SplitN(part, "=", 2)
	if len(kv) != 2 {
		return "", "", fmt.Errorf("invalid source definition: %s", part)
	}

	name, err := normalizeSourceName(kv[0])
	if err != nil {
		return "", "", err
	}

	dsn := strings.TrimSpace(kv[1])
	if dsn == "" {
		return "", "", fmt.Errorf("empty source DSN for %s", name)
	}
	if err := validateDSN(dsn); err != nil {
		return "", "", fmt.Errorf("invalid DSN for %s: %w", name, err)
	}

	return name, dsn, nil
}

func validateDSN(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return err
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return errors.New("unsupported DSN scheme")
	}
	if u.Host == "" {
		return errors.New("missing host")
	}
	return nil
}

func sanitizeQuery(raw string, requestedRows int) (string, int, error) {
	query := strings.TrimSpace(raw)
	if query == "" {
		return "", 0, ErrInvalidQuery
	}
	if len(query) > maxQueryLength {
		return "", 0, ErrInvalidQuery
	}

	if strings.Count(query, "\x00") > 0 {
		return "", 0, ErrInvalidQuery
	}
	if strings.Count(query, ";") > 0 {
		if !strings.HasSuffix(query, ";") {
			return "", 0, ErrInvalidQuery
		}
		query = strings.TrimSuffix(query, ";")
		query = strings.TrimSpace(query)
		if strings.Contains(query, ";") {
			return "", 0, ErrInvalidQuery
		}
	}

	upper := strings.ToUpper(query)
	fields := strings.Fields(upper)
	if len(fields) == 0 || (fields[0] != "SELECT" && fields[0] != "WITH") {
		return "", 0, ErrInvalidQuery
	}
	if forbiddenKeywordRegexp.MatchString(query) {
		return "", 0, ErrUnsupportedSQL
	}

	limit := defaultRowsLimit
	if requestedRows > 0 {
		limit = requestedRows
	}
	if limit > maxRowsLimit {
		limit = maxRowsLimit
	}
	if limit < 1 {
		limit = defaultRowsLimit
	}

	return query, limit, nil
}

func normalizeRowValue(v any) any {
	switch val := v.(type) {
	case nil:
		return nil
	case []byte:
		return string(val)
	case time.Time:
		return val.Format(time.RFC3339)
	case fmt.Stringer:
		return val.String()
	default:
		return fmt.Sprintf("%v", val)
	}
}
