export type OperationSignalStatus = 'loading' | 'ok' | 'warn' | 'error' | 'unknown' | 'checklist'

export interface OperationSignalSummary {
  status: OperationSignalStatus
  detailKey: string
  params?: Record<string, string | number>
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function asNumber(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}

export function loadingSignal(detailKey: string): OperationSignalSummary {
  return { status: 'loading', detailKey }
}

export function unknownSignal(detailKey: string): OperationSignalSummary {
  return { status: 'unknown', detailKey }
}

export function summarizeLiveness(data: unknown): OperationSignalSummary {
  if (isObject(data) && data.status === 'ok') {
    return { status: 'ok', detailKey: 'operations.live.health.ok' }
  }
  return { status: 'unknown', detailKey: 'operations.live.health.unknown' }
}

export function summarizeReadiness(data: unknown): OperationSignalSummary {
  if (!isObject(data)) {
    return { status: 'unknown', detailKey: 'operations.live.readiness.unknown' }
  }
  if (data.ready === true) {
    return { status: 'ok', detailKey: 'operations.live.readiness.ok' }
  }

  const checks = isObject(data.checks) ? data.checks : {}
  const failed = Object.entries(checks)
    .filter(([, value]) => !isObject(value) || value.ok !== true)
    .map(([key]) => key)

  if (failed.length > 0) {
    return {
      status: 'error',
      detailKey: 'operations.live.readiness.failedWithChecks',
      params: { checks: failed.join(', ') }
    }
  }
  return { status: 'error', detailKey: 'operations.live.readiness.failed' }
}

export function summarizeFirewall(data: unknown): OperationSignalSummary {
  if (!isObject(data)) {
    return { status: 'unknown', detailKey: 'operations.live.firewall.unknown' }
  }
  if (data.enabled !== true) {
    return { status: 'warn', detailKey: 'operations.live.firewall.disabled' }
  }

  const inspectors = asArray(data.inspectors)
  const enabled = inspectors.filter((item) => isObject(item) && item.enabled === true).length
  return {
    status: 'ok',
    detailKey: 'operations.live.firewall.ok',
    params: { enabled, total: inspectors.length }
  }
}

export function summarizeAuditStatus(data: unknown): OperationSignalSummary {
  if (!isObject(data)) {
    return { status: 'unknown', detailKey: 'operations.live.audit.unknown' }
  }
  return {
    status: 'ok',
    detailKey: 'operations.live.audit.ok',
    params: {
      mode: String(data.payload_mode || 'unknown'),
      days: typeof data.retention_days === 'number' ? data.retention_days : 'unknown',
      purged: asNumber(data.rows_purged_total)
    }
  }
}
