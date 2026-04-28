export type TenantRole = 'global_admin' | 'admin' | 'user' | 'analyst' | 'auditor' | string

export function canManageAllOrgs(role: TenantRole): boolean {
  return role === 'global_admin'
}

export function canManageOwnOrg(role: TenantRole): boolean {
  return role === 'global_admin' || role === 'admin'
}

export function centsToDollars(cents: number): string {
  return (Number.isFinite(cents) ? cents / 100 : 0).toFixed(2)
}

export function dollarsToCents(raw: string): number {
  const normalized = Number.parseFloat(raw.replace(',', '.'))
  if (!Number.isFinite(normalized) || normalized < 0) return 0
  return Math.round(normalized * 100)
}

export function scimTokenDisplayLifetime(hasPlainToken: boolean): 'one_time' | 'not_available' {
  return hasPlainToken ? 'one_time' : 'not_available'
}
