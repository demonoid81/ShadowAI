import api from './client'

export interface LegalHold {
  id: string
  target_user_id: string
  case_ref: string
  reason: string
  status: string
  created_by?: string
  created_at: string
  approved_at?: string
  approved_by?: string
  released_at?: string
  released_by?: string
  is_active: boolean
  scope_type: string
  scope_date_from?: string
  scope_date_to?: string
  selector_hash?: string
}

export interface LegalHoldCreateInput {
  target_user_id: string
  case_ref: string
  reason: string
  scope_type?: string
  scope_date_from?: string
  scope_date_to?: string
  scope_query?: unknown
}

export interface LegalHoldPreview {
  scope_type: string
  selector_hash: string
  matched_rows: number
  oldest_created_at?: string
  newest_created_at?: string
  explanation: string
}

export interface BulkLegalHoldResult {
  id: string
  success: boolean
  status?: string
  error?: string
}

export interface BulkLegalHoldResponse {
  results: BulkLegalHoldResult[]
  success_count: number
  failure_count: number
}

export interface PendingSLAResponse {
  holds: LegalHold[]
  count: number
  threshold_hours: number
}

export interface AdminEvent {
  id: string
  actor_user_id?: string
  action: string
  resource: string
  target_id?: string
  path: string
  method: string
  status_code: number
  success: boolean
  metadata_json?: string
  org_id?: string
  source_org_id?: string
  target_org_id?: string
  created_at: string
}

export interface AdminEventsResponse {
  data: AdminEvent[]
  total: number
  limit: number
  offset: number
}

export async function listLegalHolds(): Promise<LegalHold[]> {
  const { data } = await api.get<LegalHold[]>('/legal-holds')
  return data
}

export async function createLegalHold(input: LegalHoldCreateInput): Promise<LegalHold> {
  const { data } = await api.post<LegalHold>('/legal-holds', input)
  return data
}

export async function previewLegalHold(input: Pick<LegalHoldCreateInput, 'target_user_id' | 'scope_type' | 'scope_query'>): Promise<LegalHoldPreview> {
  const { data } = await api.post<LegalHoldPreview>('/legal-holds/preview', input)
  return data
}

export async function transitionLegalHold(id: string, action: string): Promise<LegalHold> {
  const { data } = await api.post<LegalHold>(`/legal-holds/${id}/${action}`)
  return data
}

export async function bulkApproveLegalHolds(ids: string[]): Promise<BulkLegalHoldResponse> {
  const { data } = await api.post<BulkLegalHoldResponse>('/legal-holds/bulk-approve', { ids })
  return data
}

export async function bulkRejectLegalHolds(ids: string[]): Promise<BulkLegalHoldResponse> {
  const { data } = await api.post<BulkLegalHoldResponse>('/legal-holds/bulk-reject', { ids })
  return data
}

export async function getPendingLegalHoldSLA(thresholdHours: number): Promise<PendingSLAResponse> {
  const { data } = await api.get<PendingSLAResponse>('/legal-holds/pending-sla', { params: { threshold_hours: thresholdHours } })
  return data
}

export async function listAdminEvents(params: Record<string, string | number | undefined>): Promise<AdminEventsResponse> {
  const { data } = await api.get<AdminEventsResponse>('/admin-events', { params })
  return data
}
