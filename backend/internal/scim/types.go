//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// PR-E2: SCIM 2.0 (RFC 7643 / RFC 7644) types for user provisioning.
package scim

import "time"

const (
	SchemaUser     = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaEntUser  = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	SchemaListResp = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaPatchOp  = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaError    = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// User is the SCIM 2.0 User resource (RFC 7643 §4.1).
type User struct {
	Schemas    []string    `json:"schemas"`
	ID         string      `json:"id,omitempty"`
	ExternalID string      `json:"externalId,omitempty"`
	UserName   string      `json:"userName"`
	Active     bool        `json:"active"`
	Emails     []Email     `json:"emails,omitempty"`
	Roles      []RoleValue `json:"roles,omitempty"`
	// Enterprise extension for department.
	EnterpriseUser *EnterpriseUser `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
	Meta           *Meta           `json:"meta,omitempty"`
}

type Email struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

type RoleValue struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type EnterpriseUser struct {
	Department string `json:"department,omitempty"`
}

type Meta struct {
	ResourceType string    `json:"resourceType,omitempty"`
	Created      time.Time `json:"created,omitempty"`
	LastModified time.Time `json:"lastModified,omitempty"`
	Location     string    `json:"location,omitempty"`
	Version      string    `json:"version,omitempty"`
}

// ListResponse is the SCIM 2.0 list response.
type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []User   `json:"Resources"`
}

// PatchRequest is the SCIM 2.0 PATCH request body.
type PatchRequest struct {
	Schemas    []string        `json:"schemas"`
	Operations []PatchOp `json:"Operations"`
}

// PatchOp is a single PATCH operation.
type PatchOp struct {
	Op    string `json:"op"`    // "add"|"remove"|"replace"
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
}

// ErrorResponse is the SCIM 2.0 error response.
type ErrorResponse struct {
	Schemas  []string `json:"schemas"`
	Status   int      `json:"status"`
	Detail   string   `json:"detail,omitempty"`
	ScimType string   `json:"scimType,omitempty"`
}

// ServiceProviderConfig describes the SCIM capabilities of this server.
type ServiceProviderConfig struct {
	Schemas               []string           `json:"schemas"`
	DocumentationURI      string             `json:"documentationUri,omitempty"`
	Patch                 Supported          `json:"patch"`
	Bulk                  BulkConfig         `json:"bulk"`
	Filter                FilterConfig       `json:"filter"`
	ChangePassword        Supported          `json:"changePassword"`
	Sort                  Supported          `json:"sort"`
	ETag                  Supported          `json:"etag"`
	AuthenticationSchemes []AuthScheme       `json:"authenticationSchemes"`
}

type Supported struct{ Supported bool `json:"supported"` }
type BulkConfig struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}
type FilterConfig struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}
type AuthScheme struct {
	Type             string `json:"type"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	SpecURI          string `json:"specUri,omitempty"`
	DocumentationURI string `json:"documentationUri,omitempty"`
	Primary          bool   `json:"primary,omitempty"`
}
