export type LegalHoldStatus = 'pending' | 'active' | 'release_pending' | 'released' | string
export type LegalHoldAction = 'approve' | 'reject' | 'release' | 'approve-release' | 'reject-release'

export function legalHoldActions(status: LegalHoldStatus): LegalHoldAction[] {
  switch (status) {
    case 'pending':
      return ['approve', 'reject']
    case 'active':
      return ['release']
    case 'release_pending':
      return ['approve-release', 'reject-release']
    default:
      return []
  }
}

export function requiresSafetyConfirm(action: LegalHoldAction): boolean {
  return action === 'release' || action === 'approve-release' || action === 'reject-release'
}

export function countByStatus<T extends { status: string }>(items: T[]): Record<string, number> {
  return items.reduce<Record<string, number>>((acc, item) => {
    acc[item.status] = (acc[item.status] ?? 0) + 1
    return acc
  }, {})
}

export function selectedPendingIDs<T extends { id: string; status: string }>(items: T[], selected: Set<string>): string[] {
  return items.filter(item => selected.has(item.id) && item.status === 'pending').map(item => item.id)
}

export function safeMetadataPreview(raw: string): string {
  if (!raw) return ''
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}
