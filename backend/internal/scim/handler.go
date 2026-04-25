//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// PR-E2: SCIM 2.0 HTTP handlers (RFC 7644).
//
// Routes (all behind SCIM bearer token auth):
//
//	GET  /scim/v2/ServiceProviderConfig  — capabilities
//	GET  /scim/v2/Users                  — list users
//	POST /scim/v2/Users                  — provision user
//	GET  /scim/v2/Users/{id}             — get user
//	PUT  /scim/v2/Users/{id}             — full replace
//	PATCH /scim/v2/Users/{id}            — partial update / deactivate
//	DELETE /scim/v2/Users/{id}           — deprovision (sets active=false)
package scim

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/domain"
)

// TokenOrgResolver resolves a bearer token hash → org_id per request.
// Implemented by scim_tokens DB lookup; allows multiple org-scoped tokens.
type TokenOrgResolver interface {
	GetOrgByTokenHash(ctx context.Context, tokenHash string) (string, error)
}

// Handler serves SCIM 2.0 endpoints.
type Handler struct {
	syncer      *UserSyncer
	bearer      string            // plaintext SCIM token (legacy / fallback)
	orgID       string            // org resolved at startup (legacy single-token path)
	tokenRepo   TokenOrgResolver  // per-request token → org lookup (scim_tokens table)
	adminAudit  adminaudit.Recorder
	baseURL     string
}

// NewHandler creates a SCIM handler.
func NewHandler(syncer *UserSyncer, bearerToken, baseURL string, adminAudit adminaudit.Recorder) *Handler {
	return &Handler{syncer: syncer, bearer: bearerToken, adminAudit: adminAudit, baseURL: baseURL}
}

// WithOrgID returns a Handler copy scoped to the given org (legacy single-token path).
func (h *Handler) WithOrgID(orgID string) *Handler {
	c := *h
	c.orgID = orgID
	c.syncer = h.syncer.WithOrgID(orgID)
	return &c
}

// WithTokenResolver attaches a per-request token resolver (scim_tokens lookup).
func (h *Handler) WithTokenResolver(r TokenOrgResolver) *Handler {
	c := *h
	c.tokenRepo = r
	return &c
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

// BearerAuth verifies the SCIM bearer token.
// When a TokenOrgResolver is configured, it looks up the token hash in scim_tokens
// per request to support multiple org-scoped tokens.
// Falls back to constant-time compare against the configured SCIM_BEARER_TOKEN.
func (h *Handler) BearerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			h.scimError(w, http.StatusUnauthorized, "invalid or missing Bearer token", "")
			return
		}

		// Per-request scim_tokens lookup (multi-token / multi-org path).
		if h.tokenRepo != nil {
			orgID, err := h.tokenRepo.GetOrgByTokenHash(r.Context(), sha256sum(token))
			if err == nil && orgID != "" {
				// Pass orgID via context; SCIM handlers read it from syncer.WithOrgID.
				next.ServeHTTP(w, r.WithContext(withSCIMOrg(r.Context(), orgID)))
				return
			}
		}

		// Legacy fallback: single static bearer token.
		if h.bearer == "" {
			h.scimError(w, http.StatusServiceUnavailable, "SCIM not configured", "")
			return
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(h.bearer)) != 1 {
			h.scimError(w, http.StatusUnauthorized, "invalid or missing Bearer token", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type scimOrgCtxKey struct{}

func withSCIMOrg(ctx context.Context, orgID string) context.Context {
	return context.WithValue(ctx, scimOrgCtxKey{}, orgID)
}

func getSCIMOrg(ctx context.Context) string {
	s, _ := ctx.Value(scimOrgCtxKey{}).(string)
	return s
}

func sha256sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// ---------------------------------------------------------------------------
// GET /scim/v2/ServiceProviderConfig
// ---------------------------------------------------------------------------

func (h *Handler) ServiceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	h.writeJSON(w, http.StatusOK, ServiceProviderConfig{
		Schemas: []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		Patch:   Supported{Supported: true},
		Bulk:    BulkConfig{Supported: false},
		Filter:  FilterConfig{Supported: true, MaxResults: 200},
		Sort:    Supported{Supported: false},
		AuthenticationSchemes: []AuthScheme{
			{Type: "oauthbearertoken", Name: "OAuth Bearer Token", Primary: true,
				Description: "Authentication via Bearer token in Authorization header"},
		},
	})
}

// ---------------------------------------------------------------------------
// GET /scim/v2/Users
// ---------------------------------------------------------------------------

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.syncerFor(r).ListUsers(r.Context())
	if err != nil {
		h.scimError(w, http.StatusInternalServerError, "failed to list users", "")
		return
	}

	// Simple filter support: attr eq "value"
	// Unsupported/malformed filters return empty results (not full list).
	filter := r.URL.Query().Get("filter")
	if filter != "" {
		filtered, ok := applyFilter(users, filter)
		if !ok {
			users = nil // unsupported filter → empty result (not full directory)
		} else {
			users = filtered
		}
	}

	resources := make([]User, 0, len(users))
	for _, u := range users {
		resources = append(resources, h.domainToSCIM(u))
	}

	h.writeJSON(w, http.StatusOK, ListResponse{
		Schemas:      []string{SchemaListResp},
		TotalResults: len(resources),
		StartIndex:   1,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

// ---------------------------------------------------------------------------
// POST /scim/v2/Users
// ---------------------------------------------------------------------------

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var scimUser User
	if err := json.NewDecoder(r.Body).Decode(&scimUser); err != nil {
		h.scimError(w, http.StatusBadRequest, "invalid JSON body", "invalidSyntax")
		return
	}

	result, err := h.syncerFor(r).Provision(r.Context(), scimUser)
	if err != nil {
		h.handleSyncError(w, err)
		return
	}

	h.recordAudit(r, result)
	w.Header().Set("Location", h.userLocation(result.User.ID))
	h.writeJSON(w, http.StatusCreated, h.domainToSCIM(*result.User))
}

// ---------------------------------------------------------------------------
// GET /scim/v2/Users/{id}
// ---------------------------------------------------------------------------

func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	u, err := h.syncerFor(r).GetUser(r.Context(), id)
	if err != nil {
		h.scimError(w, http.StatusNotFound, "user not found", "")
		return
	}
	h.writeJSON(w, http.StatusOK, h.domainToSCIM(*u))
}

// ---------------------------------------------------------------------------
// PUT /scim/v2/Users/{id}
// ---------------------------------------------------------------------------

func (h *Handler) ReplaceUser(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var scimUser User
	if err := json.NewDecoder(r.Body).Decode(&scimUser); err != nil {
		h.scimError(w, http.StatusBadRequest, "invalid JSON body", "invalidSyntax")
		return
	}

	// Ensure ID consistency.
	if scimUser.ID != "" && scimUser.ID != id {
		h.scimError(w, http.StatusBadRequest, "id in body does not match URL", "invalidValue")
		return
	}
	scimUser.ID = id

	// Fetch existing user first; PUT is full replace of an existing resource.
	existing, err := h.syncerFor(r).GetUser(r.Context(), id)
	if err != nil {
		h.scimError(w, http.StatusNotFound, "user not found", "")
		return
	}

	result, err := h.syncerFor(r).updateExisting(r.Context(), existing, scimUser, primaryEmailOrName(scimUser))
	if err != nil {
		h.handleSyncError(w, err)
		return
	}

	h.recordAudit(r, result)
	h.writeJSON(w, http.StatusOK, h.domainToSCIM(*result.User))
}

// ---------------------------------------------------------------------------
// PATCH /scim/v2/Users/{id}
// ---------------------------------------------------------------------------

func (h *Handler) PatchUser(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req PatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.scimError(w, http.StatusBadRequest, "invalid JSON body", "invalidSyntax")
		return
	}

	result, err := h.syncerFor(r).ApplyPatch(r.Context(), id, req)
	if err != nil {
		h.handleSyncError(w, err)
		return
	}

	h.recordAudit(r, result)
	h.writeJSON(w, http.StatusOK, h.domainToSCIM(*result.User))
}

// ---------------------------------------------------------------------------
// DELETE /scim/v2/Users/{id} — deprovision (sets active=false)
// ---------------------------------------------------------------------------

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	result, err := h.syncerFor(r).Deprovision(r.Context(), id)
	if err != nil {
		h.handleSyncError(w, err)
		return
	}
	h.recordAudit(r, result)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (h *Handler) domainToSCIM(u domain.User) User {
	email := u.Email
	active := u.IsActive
	scimUser := User{
		Schemas:  []string{SchemaUser, SchemaEntUser},
		ID:       u.ID,
		UserName: email,
		Active:   &active,
		Emails:   []Email{{Value: email, Primary: true, Type: "work"}},
		Meta: &Meta{
			ResourceType: "User",
			Created:      u.CreatedAt,
			LastModified: u.UpdatedAt,
			Location:     h.userLocation(u.ID),
		},
	}
	if u.SCIMExternalID != nil {
		scimUser.ExternalID = *u.SCIMExternalID
	}
	if u.Role != "" {
		scimUser.Roles = []RoleValue{{Value: u.Role, Primary: true}}
	}
	if u.Department != nil && *u.Department != "" {
		scimUser.EnterpriseUser = &EnterpriseUser{Department: *u.Department}
	}
	return scimUser
}

func (h *Handler) userLocation(id string) string {
	base := strings.TrimRight(h.baseURL, "/")
	return fmt.Sprintf("%s/Users/%s", base, id)
}

func (h *Handler) scimError(w http.ResponseWriter, status int, detail, scimType string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{
		Schemas:  []string{SchemaError},
		Status:   status,
		Detail:   detail,
		ScimType: scimType,
	})
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// syncerFor returns a per-request UserSyncer scoped to the org resolved from
// the SCIM bearer token (via scim_tokens DB lookup in BearerAuth). Falls back
// to the handler-level syncer (which carries the static config orgID).
func (h *Handler) syncerFor(r *http.Request) *UserSyncer {
	if orgID := getSCIMOrg(r.Context()); orgID != "" {
		return h.syncer.WithOrgID(orgID)
	}
	return h.syncer
}

func (h *Handler) handleSyncError(w http.ResponseWriter, err error) {
	var scimErr *SCIMError
	if errors.As(err, &scimErr) {
		h.scimError(w, scimErr.Status, scimErr.Detail, scimErr.ScimType)
		return
	}
	h.scimError(w, http.StatusInternalServerError, "internal error", "")
}

func (h *Handler) recordAudit(r *http.Request, result SyncResult) {
	if h.adminAudit == nil || result.User == nil {
		return
	}
	action := "scim_user_" + result.Action
	userID := result.User.ID
	// Use per-request org (from scim_tokens lookup or static config).
	orgID := getSCIMOrg(r.Context())
	if orgID == "" {
		orgID = h.orgID
	}
	h.adminAudit.Record(r.Context(), adminaudit.Event{
		ActorUserID: nil, // SCIM is IdP-initiated (no admin actor)
		Action:      action,
		Resource:    "user",
		TargetID:    userID,
		OrgID:       orgID,
		Path:        r.URL.Path,
		Method:      r.Method,
		StatusCode:  http.StatusOK,
		Success:     true,
		Metadata: map[string]any{
			"scim_external_id": func() string {
				if result.User.SCIMExternalID != nil {
					return *result.User.SCIMExternalID
				}
				return ""
			}(),
			"role":   result.User.Role,
			"active": result.User.IsActive,
		},
	})
}

func applyFilter(users []domain.User, filter string) ([]domain.User, bool) {
	filter = strings.TrimSpace(filter)
	// Probe the first user to check if the filter is supported.
	// If not supported, return (nil, false) — caller returns empty Resources.
	if len(users) == 0 {
		_, ok := matchFilter(domain.User{}, filter)
		return nil, ok
	}
	var result []domain.User
	for _, u := range users {
		matches, ok := matchFilter(u, filter)
		if !ok {
			return nil, false // unsupported filter → empty result
		}
		if matches {
			result = append(result, u)
		}
	}
	return result, true
}

// matchFilter returns (matches bool, ok bool).
// ok=false means the filter is malformed or uses an unsupported attribute;
// the caller should return empty results rather than the full list.
func matchFilter(u domain.User, filter string) (matches bool, ok bool) {
	parts := strings.Fields(filter)
	// Only support: <attr> eq "<value>" (3-token form).
	// Compound filters (AND/OR), other operators, and unknown formats → not supported.
	if len(parts) != 3 || !strings.EqualFold(parts[1], "eq") {
		return false, false // unsupported → empty result
	}
	attr := strings.ToLower(parts[0])
	val := strings.Trim(parts[2], `"'`)
	switch attr {
	case "username":
		return strings.EqualFold(u.Email, val), true
	case "externalid":
		return u.SCIMExternalID != nil && *u.SCIMExternalID == val, true
	case "id":
		return u.ID == val, true
	case "active":
		return fmt.Sprintf("%v", u.IsActive) == val, true
	default:
		return false, false // unknown attribute → empty result
	}
}

func primaryEmailOrName(u User) string {
	if e := primaryEmail(u); e != "" {
		return e
	}
	return u.UserName
}
