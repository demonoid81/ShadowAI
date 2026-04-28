import api from './client'

export interface LoginTokenResponse {
  token: string
  mfa_required?: false
}

export interface LoginMFAResponse {
  mfa_required: true
  mfa_token: string
}

export type LoginResponse = LoginTokenResponse | LoginMFAResponse

export interface MFASetupResponse {
  uri: string
  setup_token: string
}

export interface StatusResponse {
  status?: string
  message?: string
}

export async function loginPassword(email: string, password: string): Promise<LoginResponse> {
  const { data } = await api.post<LoginResponse>('/auth/login', { email, password })
  return data
}

export async function verifyMFA(mfaToken: string, code: string): Promise<LoginTokenResponse> {
  const { data } = await api.post<LoginTokenResponse>('/auth/mfa/verify', { mfa_token: mfaToken, code })
  return data
}

export async function breakGlassLogin(secret: string): Promise<LoginTokenResponse> {
  const { data } = await api.post<LoginTokenResponse>('/auth/break-glass', { secret })
  return data
}

export async function setupMFA(): Promise<MFASetupResponse> {
  const { data } = await api.post<MFASetupResponse>('/auth/mfa/setup')
  return data
}

export async function confirmMFA(setupToken: string, code: string): Promise<StatusResponse> {
  const { data } = await api.post<StatusResponse>('/auth/mfa/confirm', { setup_token: setupToken, code })
  return data
}

export async function disableMFA(): Promise<StatusResponse> {
  const { data } = await api.delete<StatusResponse>('/auth/mfa')
  return data
}

export async function rotateAPIKey(): Promise<{ api_key: string }> {
  const { data } = await api.post<{ api_key: string }>('/auth/rotate-api-key', {})
  return data
}

export async function revokeTokens(): Promise<StatusResponse> {
  const { data } = await api.post<StatusResponse>('/auth/revoke')
  return data
}
