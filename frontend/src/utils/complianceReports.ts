export type ComplianceReportType = 'access_review' | 'retention_report' | 'evidence_manifest' | 'not_collected' | 'unknown'
export type ComplianceStatus = 'ok' | 'warn' | 'fail' | 'unknown'

export interface ComplianceReportSummary {
  type: ComplianceReportType
  title: string
  status: ComplianceStatus
  generatedAt?: string
  period?: string
  total: number
  passed: number
  failed: number
  notCollected: number
  findings: Array<{ code: string; severity?: string; description?: string; count?: number }>
  rows: Array<Record<string, unknown>>
  raw: unknown
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function asNumber(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}

function periodFromManifest(manifest: Record<string, unknown> | undefined): string {
  if (!manifest || !isObject(manifest.period)) return ''
  const from = asString(manifest.period.from)
  const to = asString(manifest.period.to)
  return from && to ? `${from} - ${to}` : ''
}

function summarizeAccessReview(raw: Record<string, unknown>): ComplianceReportSummary {
  const manifest = isObject(raw.manifest) ? raw.manifest : undefined
  const usersSummary = isObject(raw.users_summary) ? raw.users_summary : {}
  const findings = asArray(raw.findings).filter(isObject).map(item => ({
    code: asString(item.code) || 'finding',
    severity: asString(item.severity),
    description: asString(item.description),
    count: asNumber(item.count)
  }))
  const privileged = asArray(raw.privileged_users).filter(isObject)
  return {
    type: 'access_review',
    title: 'Access review',
    status: findings.some(item => item.severity === 'critical' || item.severity === 'high') ? 'fail' : findings.length ? 'warn' : 'ok',
    generatedAt: asString(manifest?.generated_at),
    period: periodFromManifest(manifest),
    total: asNumber(usersSummary.total),
    passed: Math.max(0, asNumber(usersSummary.total) - findings.reduce((sum, item) => sum + (item.count ?? 0), 0)),
    failed: findings.length,
    notCollected: 0,
    findings,
    rows: privileged,
    raw
  }
}

function summarizeRetentionReport(raw: Record<string, unknown>): ComplianceReportSummary {
  const bundles = asArray(raw.bundles).filter(isObject)
  const violationCount = asNumber(raw.violation_count)
  return {
    type: 'retention_report',
    title: 'Evidence retention',
    status: violationCount > 0 ? 'fail' : 'ok',
    generatedAt: asString(raw.generated_at),
    total: asNumber(raw.total_bundles),
    passed: asNumber(raw.compliant_count),
    failed: violationCount,
    notCollected: 0,
    findings: bundles
      .filter(item => asArray(item.violations).length > 0)
      .map(item => ({
        code: asString(item.key) || 'bundle_violation',
        severity: 'high',
        description: asArray(item.violations).map(String).join(', '),
        count: asArray(item.violations).length
      })),
    rows: bundles,
    raw
  }
}

function summarizeEvidenceManifest(raw: Record<string, unknown>): ComplianceReportSummary {
  const controls = asArray(raw.controls).filter(isObject)
  const notCollected = controls.filter(item => item.status === 'not_collected')
  const templates = controls.filter(item => item.status === 'template')
  return {
    type: 'evidence_manifest',
    title: 'Evidence collection manifest',
    status: notCollected.length > 0 ? 'warn' : 'ok',
    generatedAt: asString(raw.generated_at),
    period: periodFromManifest(raw),
    total: controls.length,
    passed: controls.filter(item => item.status === 'collected').length,
    failed: 0,
    notCollected: notCollected.length,
    findings: [
      ...notCollected.map(item => ({
        code: asString(item.id) || 'not_collected',
        severity: 'medium',
        description: asString(item.reason) || asString(item.description),
        count: 1
      })),
      ...templates.map(item => ({
        code: asString(item.id) || 'template',
        severity: 'informational',
        description: asString(item.description),
        count: 1
      }))
    ],
    rows: controls,
    raw
  }
}

function summarizeNotCollected(raw: unknown[]): ComplianceReportSummary {
  const rows = raw.filter(isObject)
  return {
    type: 'not_collected',
    title: 'Not collected controls',
    status: rows.length > 0 ? 'warn' : 'ok',
    total: rows.length,
    passed: 0,
    failed: 0,
    notCollected: rows.length,
    findings: rows.map(item => ({
      code: asString(item.id) || 'not_collected',
      severity: 'medium',
      description: asString(item.reason) || asString(item.description),
      count: 1
    })),
    rows,
    raw
  }
}

export function summarizeComplianceReport(raw: unknown): ComplianceReportSummary {
  if (Array.isArray(raw)) return summarizeNotCollected(raw)
  if (!isObject(raw)) {
    return {
      type: 'unknown',
      title: 'Unknown report',
      status: 'unknown',
      total: 0,
      passed: 0,
      failed: 0,
      notCollected: 0,
      findings: [],
      rows: [],
      raw
    }
  }
  if (isObject(raw.users_summary) && Array.isArray(raw.findings)) return summarizeAccessReview(raw)
  if (Array.isArray(raw.bundles) && 'violation_count' in raw) return summarizeRetentionReport(raw)
  if (Array.isArray(raw.controls) && isObject(raw.file_sha256)) return summarizeEvidenceManifest(raw)
  return {
    type: 'unknown',
    title: 'Unknown report',
    status: 'unknown',
    generatedAt: asString(raw.generated_at),
    total: 0,
    passed: 0,
    failed: 0,
    notCollected: 0,
    findings: [],
    rows: [raw],
    raw
  }
}

export function parseComplianceJSON(text: string): ComplianceReportSummary {
  return summarizeComplianceReport(JSON.parse(text))
}
