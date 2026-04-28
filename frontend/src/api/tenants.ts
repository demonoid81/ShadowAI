import api from './client'

export interface Organization {
  id: string
  name: string
  slug: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface SCIMToken {
  id: string
  org_id: string
  label?: string
  is_active: boolean
  created_at: string
  last_used_at?: string | null
}

export interface SCIMTokenCreateResponse {
  token: SCIMToken
  plain_token: string
  warning: string
}

export interface OrgBudgetPolicy {
  org_id: string
  monthly_limit_cents: number
  mode: 'disabled' | 'observe' | 'enforce'
  updated_at?: string
  updated_by?: string
}

export interface OrgBudgetUsage {
  org_id: string
  period_start: string
  spent_cents: number
}

export interface OrgBudgetStatus {
  policy: OrgBudgetPolicy
  usage: OrgBudgetUsage
  remaining_cents: number
}

export interface OrgUpdateInput {
  name?: string
  slug?: string
  is_active?: boolean
}

export async function listOrganizations(): Promise<Organization[]> {
  const { data } = await api.get<Organization[]>('/orgs')
  return data
}

export async function getOrganization(orgID: string): Promise<Organization> {
  const { data } = await api.get<Organization>(`/orgs/${orgID}`)
  return data
}

export async function createOrganization(input: { name: string; slug: string }): Promise<Organization> {
  const { data } = await api.post<Organization>('/orgs', input)
  return data
}

export async function updateOrganization(orgID: string, input: OrgUpdateInput): Promise<Organization> {
  const { data } = await api.patch<Organization>(`/orgs/${orgID}`, input)
  return data
}

export async function listSCIMTokens(orgID: string): Promise<SCIMToken[]> {
  const { data } = await api.get<SCIMToken[]>(`/orgs/${orgID}/scim-tokens`)
  return data
}

export async function createSCIMToken(orgID: string, label: string): Promise<SCIMTokenCreateResponse> {
  const { data } = await api.post<SCIMTokenCreateResponse>(`/orgs/${orgID}/scim-tokens`, { label })
  return data
}

export async function revokeSCIMToken(orgID: string, tokenID: string): Promise<void> {
  await api.delete(`/orgs/${orgID}/scim-tokens/${tokenID}`)
}

export async function getOrgBudget(orgID: string): Promise<OrgBudgetStatus> {
  const { data } = await api.get<OrgBudgetStatus>(`/orgs/${orgID}/budget`)
  return data
}

export async function updateOrgBudget(
  orgID: string,
  input: Pick<OrgBudgetPolicy, 'monthly_limit_cents' | 'mode'>
): Promise<OrgBudgetPolicy> {
  const { data } = await api.put<OrgBudgetPolicy>(`/orgs/${orgID}/budget`, input)
  return data
}
