# LLM Provider Assessment Template

Copy this file once per provider/model/use case. Keep completed assessments in
the operator's compliance repository or evidence collection workspace.

## 1. Intake

| Field | Value |
|-------|-------|
| Assessment ID | |
| Provider | |
| Model(s) | |
| Business owner | |
| Security owner | |
| Privacy/legal owner | |
| Platform owner | |
| Org ID / tenant | |
| Department(s) | |
| Use case | |
| Requested go-live date | |
| Data sensitivity | standard / confidential / restricted |

## 2. Data Handling

| Question | Answer | Evidence link |
|----------|--------|---------------|
| What data categories will be sent to the provider? | | |
| Will prompts or responses include personal data? | | |
| Will prompts or responses include regulated data? | | |
| What is the provider retention period? | | |
| Can customer data be used for model training? | | |
| Is training disabled by contract or configuration? | | |
| What deletion rights exist? | | |
| What region(s) process/store data? | | |

## 3. Security and Compliance

| Question | Answer | Evidence link |
|----------|--------|---------------|
| SOC 2 / ISO / equivalent assurance available? | | |
| Security whitepaper reviewed? | | |
| DPA reviewed and accepted? | | |
| Subprocessor list reviewed? | | |
| Incident notification terms acceptable? | | |
| Provider status page / SLA reviewed? | | |
| Abuse/safety controls documented? | | |

## 4. ShadowAI Governance Mapping

| Field | Value |
|-------|-------|
| Governance mode | context_scoped / role_based / allowlist_strict |
| Provider identifier | |
| Allowed model(s) | |
| Allowed role(s) | |
| Allowed department(s) | |
| Maximum sensitivity | standard / confidential / restricted |
| Explicit deny contexts | |
| Governance policy ref | |

Example policy fragment:

```json
{
  "department": "",
  "role": "*",
  "sensitivity": ["standard"],
  "rules": [
    {"provider": "", "models": [""]}
  ]
}
```

## 5. Decision

| Field | Value |
|-------|-------|
| Decision | approved / conditional / denied / expired / revoked |
| Decision date | |
| Next review date | |
| Conditions / restrictions | |
| Approver | |
| Evidence bundle ref | |

## 6. Required Sign-Off

- [ ] Business owner
- [ ] Security owner
- [ ] Privacy/legal owner
- [ ] Platform owner
- [ ] Compliance owner

## 7. Post-Approval Checks

- [ ] Provider/model added to approved provider register.
- [ ] Governance policy updated.
- [ ] Admin event for policy update captured.
- [ ] Test allowed request succeeds.
- [ ] Test unapproved provider/model is denied before upstream call.
- [ ] Evidence ref attached to assessment.
