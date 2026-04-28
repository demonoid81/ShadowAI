export type AuthDestination = 'dashboard' | 'mfa_verify' | 'security_enrollment'

export interface MinimalClaims {
  role?: string
  mfa_verified?: boolean
  break_glass?: boolean
}

export function nextAuthDestination(claims: MinimalClaims | null, mfaRequired: boolean): AuthDestination {
  if (mfaRequired) return 'mfa_verify'
  if ((claims?.role === 'admin' || claims?.role === 'global_admin') && !claims.mfa_verified && !claims.break_glass) {
    return 'security_enrollment'
  }
  return 'dashboard'
}

export function shouldShowBreakGlassWarning(secret: string): boolean {
  return secret.trim().length > 0
}

export function isOIDCEntrypointSafe(path: string): boolean {
  return path === '/api/auth/oidc/login'
}
