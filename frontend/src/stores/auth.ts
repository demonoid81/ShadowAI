import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import api from '../api/client'

interface JWTClaims {
  user_id?: string
  email?: string
  role?: string
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

  const claims = computed(() => (token.value ? parseJWT(token.value) : null))
  const role = computed(() => claims.value?.role ?? '')
  const isAdmin = computed(() => role.value === 'admin')

  async function login(email: string, password: string) {
    const { data } = await api.post('/auth/login', { email, password })
    token.value = data.token
    localStorage.setItem('token', data.token)
  }

  function logout() {
    token.value = ''
    user.value = null
    localStorage.removeItem('token')
  }

  return { token, user, claims, role, isAdmin, login, logout }
})
