# bd ShadowAI-rhl.7 — примеры

## Happy path 1 — approved provider for standard data

Business owner requests OpenAI for support triage with standard data only.
Security/privacy approve the provider, register row status becomes `approved`,
and platform adds a `context_scoped` governance rule for `support + standard`.

Ожидаемый outcome: approved provider/model can be used; confidential/restricted
contexts remain denied unless explicitly approved.

## Happy path 2 — existing provider annual review

Provider was approved last year for engineering copilots. Compliance owner
checks SOC report, subprocessor list and retention terms, then updates
`next_review_date`.

Ожидаемый outcome: status remains `approved`; governance rule unchanged; new
evidence ref attached.

## Edge case 1 — conditional approval

Provider is acceptable for EU region only and training must be disabled.

Ожидаемый outcome: register status `conditional`; governance rule must include
only the approved org/department/sensitivity. Conditions are recorded in the
assessment.

## Edge case 2 — expired review

`next_review_date` passed, but provider remains in live governance policy.

Ожидаемый outcome: operator must either re-approve or remove/narrow the
governance rule. Expired approval must not be treated as approved.

## Failure case — governance without approval

Admin adds `provider=anthropic, model=*` to governance policy, but no approved
provider register row exists.

Ожидаемый outcome: this is a vendor-risk control failure. Remove the policy
rule or complete assessment before allowing production use.
