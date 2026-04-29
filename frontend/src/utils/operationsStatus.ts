export interface ProductionDetailItem {
  key: string
  labelKey: string
  value: string
}

const knownDetailOrder = [
  'query_configured',
  'value',
  'last_success_configured',
  'last_success_at',
  'age_seconds',
  'stale_after_seconds'
]

export function formatProductionDetails(details?: Record<string, unknown>): ProductionDetailItem[] {
  if (!details) return []
  return Object.entries(details)
    .sort(([left], [right]) => detailOrder(left) - detailOrder(right) || left.localeCompare(right))
    .map(([key, value]) => ({
      key,
      labelKey: `operations.detailLabels.${knownDetailOrder.includes(key) ? key : 'other'}`,
      value: formatDetailValue(key, value)
    }))
}

function detailOrder(key: string): number {
  const index = knownDetailOrder.indexOf(key)
  return index === -1 ? knownDetailOrder.length : index
}

function formatDetailValue(key: string, value: unknown): string {
  if (key === 'age_seconds' || key === 'stale_after_seconds') {
    return formatSeconds(value)
  }
  if (key === 'last_success_at' && typeof value === 'string') {
    const parsed = new Date(value)
    return Number.isNaN(parsed.getTime()) ? value : parsed.toISOString()
  }
  if (Array.isArray(value)) return value.join(', ')
  if (value && typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

export function formatSeconds(value: unknown): string {
  const total = typeof value === 'number' && Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0
  if (total < 60) return `${total}s`
  const days = Math.floor(total / 86400)
  const hours = Math.floor((total % 86400) / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  const parts: string[] = []
  if (days > 0) parts.push(`${days}d`)
  if (hours > 0) parts.push(`${hours}h`)
  if (minutes > 0 && days === 0) parts.push(`${minutes}m`)
  return parts.length > 0 ? parts.join(' ') : `${total}s`
}
