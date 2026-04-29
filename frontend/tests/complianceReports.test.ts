import { strict as assert } from 'node:assert'
import { parseComplianceJSON, summarizeComplianceReport } from '../src/utils/complianceReports'

const access = summarizeComplianceReport({
  manifest: { generated_at: '2026-04-01T00:00:00Z', period: { from: '2026-01-01', to: '2026-03-31' } },
  users_summary: { total: 10 },
  privileged_users: [{ id: 'u1', role: 'admin' }],
  findings: [{ code: 'admin_without_mfa', severity: 'critical', description: 'missing MFA', count: 1 }]
})
assert.equal(access.type, 'access_review')
assert.equal(access.status, 'fail')
assert.equal(access.failed, 1)
assert.equal(access.rows.length, 1)

const retention = summarizeComplianceReport({
  generated_at: '2026-04-01T00:00:00Z',
  total_bundles: 2,
  compliant_count: 1,
  violation_count: 1,
  bundles: [{ key: 'global.zip', violations: ['missing_object_lock'] }]
})
assert.equal(retention.type, 'retention_report')
assert.equal(retention.status, 'fail')
assert.equal(retention.findings[0].description, 'missing_object_lock')

const manifest = summarizeComplianceReport({
  generated_at: '2026-04-01T00:00:00Z',
  period: { from: '2026-01-01', to: '2026-03-31' },
  controls: [
    { id: 'chain_verify', status: 'collected' },
    { id: 'retention', status: 'not_collected', reason: 'bucket unavailable' },
    { id: 'access_review_checklist', status: 'template' }
  ],
  file_sha256: { 'x.json': 'abc' }
})
assert.equal(manifest.type, 'evidence_manifest')
assert.equal(manifest.notCollected, 1)
assert.equal(manifest.findings.length, 2)

const notCollected = summarizeComplianceReport([{ id: 'x', reason: 'missing env' }])
assert.equal(notCollected.type, 'not_collected')
assert.equal(notCollected.status, 'warn')
assert.equal(notCollected.notCollected, 1)

assert.throws(() => parseComplianceJSON('{bad-json'))
assert.equal(parseComplianceJSON('{"hello":"world"}').type, 'unknown')

console.log('complianceReports tests ok')
