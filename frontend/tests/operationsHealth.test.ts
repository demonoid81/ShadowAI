import { strict as assert } from 'node:assert'
import {
  summarizeAuditStatus,
  summarizeFirewall,
  summarizeLiveness,
  summarizeReadiness
} from '../src/utils/operationsHealth'

const live = summarizeLiveness({ status: 'ok' })
assert.equal(live.status, 'ok')
assert.equal(live.detailKey, 'operations.live.health.ok')

const degraded = summarizeReadiness({
  ready: false,
  checks: {
    db: { ok: true },
    redis: { ok: false, error: 'ping failed' }
  }
})
assert.equal(degraded.status, 'error')
assert.equal(degraded.params?.checks, 'redis')

const ready = summarizeReadiness({ ready: true, checks: { db: { ok: true }, redis: { ok: true } } })
assert.equal(ready.status, 'ok')

const firewallDisabled = summarizeFirewall({ enabled: false, inspectors: [] })
assert.equal(firewallDisabled.status, 'warn')
assert.equal(firewallDisabled.detailKey, 'operations.live.firewall.disabled')

const firewallEnabled = summarizeFirewall({
  enabled: true,
  inspectors: [{ enabled: true }, { enabled: false }, { enabled: true }]
})
assert.equal(firewallEnabled.status, 'ok')
assert.equal(firewallEnabled.params?.enabled, 2)
assert.equal(firewallEnabled.params?.total, 3)

const audit = summarizeAuditStatus({
  payload_mode: 'byok',
  retention_days: 90,
  rows_purged_total: 12
})
assert.equal(audit.status, 'ok')
assert.equal(audit.params?.mode, 'byok')
assert.equal(audit.params?.days, 90)
assert.equal(audit.params?.purged, 12)

const unknownAudit = summarizeAuditStatus(null)
assert.equal(unknownAudit.status, 'unknown')

console.log('operationsHealth tests ok')
