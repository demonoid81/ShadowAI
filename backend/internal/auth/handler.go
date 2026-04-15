package auth

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/shadowai/backend/internal/domain"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string `json:"token"`
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type rotateAPIKeyRequest struct {
	UserID string `json:"user_id"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type apiKeyResponse struct {
	APIKey string `json:"api_key"`
}

type statusResponse struct {
	Message string `json:"message"`
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "email and password are required"})
		return
	}

	token, err := h.service.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid credentials"})
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{Token: token})
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "email and password are required"})
		return
	}
	var err error
	if req.Role == "" {
		req.Role = RoleUser
	}
	req.Role, err = NormalizeRole(req.Role)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid role"})
		return
	}

	// Allow open registration only if no users exist (first user becomes admin)
	count, err := h.service.GetRepo().CountUsers(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal server error"})
		return
	}

	if count > 0 {
		// Require admin role for subsequent registrations
		claims := GetClaims(r.Context())
		if claims == nil || claims.Role != RoleAdmin {
			writeJSON(w, http.StatusForbidden, errorResponse{Error: "only admins can register new users"})
			return
		}
	} else {
		// First user is always admin
		req.Role = RoleAdmin
	}

	user, err := h.service.Register(r.Context(), req.Email, req.Password, req.Role)
	if err != nil {
		if err == ErrUserExists {
			writeJSON(w, http.StatusConflict, errorResponse{Error: "user already exists"})
			return
		}
		if err == ErrWeakPassword {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "password must be at least 12 characters"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal server error"})
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.service.GetRepo().ListUsers(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal server error"})
		return
	}
	if users == nil {
		users = []domain.User{}
	}
	for i := range users {
		users[i].APIKey = ""
	}
	writeJSON(w, http.StatusOK, users)
}

func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	user, err := h.service.GetRepo().GetByID(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "user not found"})
		return
	}
	user.APIKey = ""
	writeJSON(w, http.StatusOK, user)
}

func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	existing, err := h.service.GetRepo().GetByID(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "user not found"})
		return
	}

	var req struct {
		Email    string `json:"email"`
		Role     string `json:"role"`
		IsActive *bool  `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}

	if req.Email != "" {
		existing.Email = req.Email
	}
	if req.Role != "" {
		role, err := NormalizeRole(req.Role)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid role"})
			return
		}
		existing.Role = role
	}
	if req.IsActive != nil {
		existing.IsActive = *req.IsActive
	}

	if err := h.service.GetRepo().UpdateUser(r.Context(), existing); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal server error"})
		return
	}

	existing.APIKey = ""
	writeJSON(w, http.StatusOK, existing)
}

func (h *Handler) RevokeTokens(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}

	if err := h.service.RevokeTokens(r.Context(), claims.UserID); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal server error"})
		return
	}

	writeJSON(w, http.StatusOK, statusResponse{Message: "all tokens revoked"})
}

func (h *Handler) RotateAPIKey(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}

	var req rotateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.UserID = ""
	}

	targetID := claims.UserID
	if req.UserID != "" {
		if claims.Role != RoleAdmin {
			writeJSON(w, http.StatusForbidden, errorResponse{Error: "forbidden"})
			return
		}
		targetID = req.UserID
	}

	newKey, err := h.service.RotateAPIKey(r.Context(), targetID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal"})
		return
	}

	writeJSON(w, http.StatusOK, apiKeyResponse{APIKey: newKey})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
