# bd ShadowAI-rhl.8 — примеры

## Happy path 1 — customer supports OIDC

Клиент использует Okta/Azure/Google Workspace с OIDC authorization-code flow.
ShadowAI подключается через OIDC, роли идут через groups claim, provisioning
идёт через SCIM. SAML не нужен.

Ожидаемый ответ: supported path, no product gap for this customer.

## Happy path 2 — customer asks if SAML exists

Security questionnaire спрашивает: "Do you support SAML SSO?"

Ожидаемый ответ: SAML SSO is not currently implemented. ShadowAI supports OIDC
SSO and SCIM. If SAML is mandatory, it is a customer-dependent implementation
requiring IdP metadata and claims contract.

## Edge case 1 — customer requires SAML for admin MFA proof

IdP не отдаёт OIDC `amr` / `acr`, но отдаёт MFA через SAML
`AuthnContextClassRef`.

Ожидаемый outcome: SAML implementation может быть justified, но только после
фиксированного mapping contract и tests for MFA-not-confirmed.

## Edge case 2 — multi-tenant deployment

Один IdP обслуживает несколько ShadowAI org. SAML assertion содержит department,
но не содержит trusted org binding.

Ожидаемый outcome: implementation нельзя начинать без tenant binding decision.
Org не должен извлекаться из spoofable header.

## Failure case — unsafe claim

SAML assertion содержит `role=global_admin`, но customer не включал explicit
dangerous opt-in для global admin provisioning.

Ожидаемый outcome: assertion rejected or downgraded according to configured
mapping; нельзя автоматически выдавать global_admin.
