import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import {
  breakGlassLogin,
  loginPassword,
  verifyMFA,
  type LoginResponse
} from '../api/auth'

interface JWTClaims {
  user_id?: string
  email?: string
  role?: string
  org_id?: string
  department?: string
  mfa_verified?: boolean
  break_glass?: boolean
  exp?: number
}

function parseJWT(token: string): JWTClaims | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))
    return payload as JWTClaims
  } catch {
    return null
  }
}

export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem('token') || '')
  const user = ref<any>(null)
  const pendingMFAToken = ref(sessionStorage.getItem('mfa_token') || '')

  const claims = computed(() => (token.value ? parseJWT(token.value) : null))
  const role = computed(() => claims.value?.role ?? '')
  const isGlobalAdmin = computed(() => role.value === 'global_admin')
  const isAdmin = computed(() => role.value === 'admin' || isGlobalAdmin.value)

  function setToken(nextToken: string) {
    token.value = nextToken
    localStorage.setItem('token', nextToken)
    pendingMFAToken.value = ''
    sessionStorage.removeItem('mfa_token')
  }

  async function login(email: string, password: string): Promise<LoginResponse> {
    const data = await loginPassword(email, password)
    if ('mfa_required' in data && data.mfa_required) {
      pendingMFAToken.value = data.mfa_token
      sessionStorage.setItem('mfa_token', data.mfa_token)
      return data
    }
    setToken(data.token)
    return data
  }

  async function completeMFA(code: string) {
    const data = await verifyMFA(pendingMFAToken.value, code)
    setToken(data.token)
  }

  async function breakGlass(secret: string) {
    const data = await breakGlassLogin(secret)
    setToken(data.token)
  }

  function logout() {
    token.value = ''
    user.value = null
    pendingMFAToken.value = ''
    localStorage.removeItem('token')
    sessionStorage.removeItem('mfa_token')
  }

  return { token, user, claims, role, isAdmin, isGlobalAdmin, pendingMFAToken, login, completeMFA, breakGlass, logout }
})
