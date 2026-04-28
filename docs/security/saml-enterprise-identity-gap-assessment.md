# SAML Enterprise Identity Gap Assessment

Date: 2026-04-28
Status: IAM1 assessment complete; SAML implementation is customer-dependent.

## 1. Executive Summary

ShadowAI currently supports enterprise identity through OIDC SSO, SCIM 2.0
provisioning, IdP MFA claim enforcement, local TOTP MFA, break-glass access,
and per-organization SCIM tokens.

SAML SSO is not implemented. This is an explicit product gap, not a hidden
capability. The current position is:

- OIDC is the supported SSO protocol for enterprise deployments.
- SCIM is the supported lifecycle provisioning protocol.
- SAML should be implemented only when a target customer cannot use OIDC and
  provides a concrete IdP metadata and claims contract.
- Until then, SAML remains customer-dependent future work.

This document gives sales, security review, and implementation teams a
consistent answer for SAML requirements without overstating current support.

## 2. Current Identity Capabilities

| Capability | Status | Evidence |
|------------|--------|----------|
| OIDC authorization code flow | Supported | `backend/internal/oidcauth/` |
| OIDC group to role mapping | Supported | `OIDC_ROLE_MAP_JSON` |
| OIDC department claim mapping | Supported | `OIDC_DEPARTMENT_CLAIM` |
| OIDC admin MFA claim enforcement | Supported | `OIDC_REQUIRE_MFA_FOR_ADMIN`, `amr` / `acr` checks |
| SCIM 2.0 user lifecycle | Supported | `/scim/v2/*` |
| Per-org SCIM tokens | Supported | `scim_tokens` table and org admin APIs |
| Local TOTP MFA | Supported | `/api/auth/mfa/*` |
| Break-glass access | Supported | `/api/auth/break-glass` |
| SAML SP login | Not implemented | This document |
| SAML metadata endpoint | Not implemented | This document |
| SAML assertion validation | Not implemented | This document |

## 3. OIDC vs SAML Requirements Matrix

| Requirement | OIDC path today | SAML path if required | Current decision |
|-------------|-----------------|-----------------------|------------------|
| Browser SSO | Authorization code flow | SP-initiated SAML WebSSO | OIDC supported |
| Role mapping | Groups claim to ShadowAI role | Attribute / group assertion mapping | OIDC supported; SAML future |
| Department mapping | Configurable claim name | Attribute mapping | OIDC supported; SAML future |
| Admin MFA proof | `amr` / `acr` claim allowlist | AuthnContextClassRef / custom attribute | OIDC supported; SAML future |
| User lifecycle | SCIM 2.0 | SCIM remains preferred even with SAML | Supported |
| Tenant org binding | User `org_id`, SCIM token org | SAML attribute or IdP app per org | Future design required |
| Logout | JWT expiry / app session | SAML SLO optional and IdP-specific | Not required for current OIDC path |
| Evidence | Admin events, access review, SIEM | Same event model plus SAML metadata | Future implementation |

## 4. When SAML Is Required

SAML should be considered required only when at least one of these conditions is
true:

1. The target customer IdP cannot issue OIDC authorization-code tokens for this
   application.
2. Customer policy explicitly mandates SAML SP integration and rejects OIDC.
3. Procurement or security review requires SAML metadata exchange as a hard
   control.
4. The customer's IdP MFA proof is only exposed through SAML
   `AuthnContextClassRef` or SAML attributes.

If none of these are true, the recommended integration remains OIDC + SCIM.

## 5. Minimum Customer Inputs Before SAML Implementation

A SAML implementation should not start without the following customer-specific
inputs:

- IdP metadata XML with entity ID, SSO URL, signing certificate, and supported
  binding.
- Required SP entity ID and ACS URL format.
- NameID format and stable subject requirement.
- Email attribute name and verification semantics.
- Group / role attribute name and mapping to `user`, `analyst`, `auditor`,
  `admin`, and optionally `global_admin`.
- Department attribute name for G3 department/sensitivity routing.
- MFA assertion source: `AuthnContextClassRef` values or custom attributes.
- Tenant binding model: one IdP app per org, explicit org attribute, or
  operator-side org assignment.
- Certificate rotation process and expected overlap window.
- Requirement decision on SAML Single Logout. Default recommendation: out of
  scope for v1 unless customer-mandated.

## 6. Proposed SAML Adapter Scope

If a customer makes SAML mandatory, implement a separate enterprise-only SAML
adapter instead of replacing OIDC.

### Scope In

- `SAML_ENABLED` production-gated config.
- SP metadata endpoint.
- SP-initiated login endpoint.
- ACS callback endpoint.
- Signed assertion validation.
- Replay protection through assertion ID cache.
- Attribute mapping to email, role, department, and optional org.
- Admin MFA enforcement via AuthnContextClassRef / configured attribute.
- User sync path equivalent to OIDC subject match, verified email link, and
  optional auto-provision.
- Admin audit events for login success, denied login, metadata load error,
  MFA-not-confirmed, and mapping failure.

### Scope Out for v1

- IdP-initiated SSO unless the customer requires it and CSRF/replay controls are
  explicitly designed.
- SAML Single Logout unless the customer requires it.
- JIT global_admin provisioning by default. It must remain dangerous opt-in, as
  with the existing OIDC global admin policy.
- Replacing SCIM. SCIM remains the lifecycle source of truth.

## 7. Security Invariants for Any Future SAML Work

- Accept signed assertions only.
- Reject unsigned or weakly signed responses.
- Enforce audience, issuer, recipient, destination, NotBefore, and NotOnOrAfter.
- Require assertion replay protection.
- Do not trust request headers for role, department, or org assignment.
- Keep SAML subject stable and separate from OIDC subject.
- Do not auto-link by email unless the email trust condition is explicit.
- Preserve tenant isolation: SAML-derived org must be verified against an
  operator-approved mapping.
- Emit admin events and SIEM events for all successful and denied SAML logins.
- Keep break-glass independent of SAML availability.

## 8. Evidence and Audit Expectations

If SAML is implemented later, the following artifacts must be added to the
existing evidence workflow:

- SAML configuration snapshot with sensitive values redacted.
- IdP metadata fingerprint and signing certificate fingerprint.
- Login success / denied admin events with `auth_method="saml"`.
- Access review fields showing SAML-linked users, analogous to OIDC/SCIM link
  status.
- Runbook for certificate rotation and metadata reload.
- Tests for invalid signature, expired assertion, wrong audience, replayed
  assertion, MFA-not-confirmed, role mapping, and tenant mapping.

## 9. Current Customer Answer

Use this wording in questionnaires:

> ShadowAI supports enterprise SSO via OIDC authorization-code flow and user
> lifecycle provisioning via SCIM 2.0. SAML SSO is not currently implemented.
> If a customer requires SAML and cannot use OIDC, SAML is treated as a
> customer-dependent implementation item requiring IdP metadata, attribute
> mapping, MFA assertion semantics, and tenant binding requirements.

Do not claim:

- "SAML is supported."
- "SAML is on by default."
- "SAML can be enabled with a config flag."
- "SAML and OIDC are equivalent in the current release."

## 10. Decision

IAM1 closes the SAML ambiguity by making the current state explicit:

- Current supported enterprise path: OIDC + SCIM + MFA claim enforcement.
- SAML support: not implemented.
- Product position: customer-dependent future adapter, not a hidden blocker for
  OIDC-capable enterprise pilots.
- Next implementation trigger: signed customer requirement with IdP metadata and
  claims contract.
