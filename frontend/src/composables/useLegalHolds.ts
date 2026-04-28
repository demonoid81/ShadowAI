import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  bulkApproveLegalHolds,
  bulkRejectLegalHolds,
  createLegalHold,
  getPendingLegalHoldSLA,
  listLegalHolds,
  previewLegalHold,
  transitionLegalHold,
  type BulkLegalHoldResponse,
  type LegalHold,
  type LegalHoldCreateInput,
  type LegalHoldPreview,
  type PendingSLAResponse
} from '../api/legal'
import { countByStatus, requiresSafetyConfirm, selectedPendingIDs, type LegalHoldAction } from '../utils/legalHoldUi'

export function useLegalHolds() {
  const { t } = useI18n()
  const holds = ref<LegalHold[]>([])
  const selectedIds = ref(new Set<string>())
  const preview = ref<LegalHoldPreview | null>(null)
  const pendingSLA = ref<PendingSLAResponse | null>(null)
  const bulkResult = ref<BulkLegalHoldResponse | null>(null)
  const error = ref('')
  const success = ref('')
  const loading = ref(false)
  const saving = ref(false)
  const slaThresholdHours = ref(24)
  const scopeQueryText = ref('{"where":{"policy_action":"blocked"}}')
  const draft = reactive<LegalHoldCreateInput>({
    target_user_id: '',
    case_ref: '',
    reason: '',
    scope_type: 'whole_user'
  })

  const statusCounts = computed(() => countByStatus(holds.value))

  function setSuccess(message: string) {
    success.value = message
    error.value = ''
  }

  function setError(err: unknown, fallback: string) {
    const anyErr = err as { response?: { data?: { error?: string } } }
    error.value = anyErr.response?.data?.error || fallback
    success.value = ''
  }

  function buildCreatePayload(): LegalHoldCreateInput {
    const payload: LegalHoldCreateInput = {
      target_user_id: draft.target_user_id.trim(),
      case_ref: draft.case_ref.trim(),
      reason: draft.reason.trim(),
      scope_type: draft.scope_type || 'whole_user'
    }
    if (payload.scope_type === 'date_range') {
      if (draft.scope_date_from) payload.scope_date_from = new Date(draft.scope_date_from).toISOString()
      if (draft.scope_date_to) payload.scope_date_to = new Date(draft.scope_date_to).toISOString()
    }
    if (payload.scope_type === 'query_scope') payload.scope_query = JSON.parse(scopeQueryText.value)
    return payload
  }

  async function loadHolds() {
    loading.value = true
    try {
      holds.value = await listLegalHolds()
      selectedIds.value = new Set()
    } catch (err) {
      setError(err, t('legalHolds.errors.loadFailed'))
    } finally {
      loading.value = false
    }
  }

  async function createHold() {
    saving.value = true
    try {
      const hold = await createLegalHold(buildCreatePayload())
      holds.value = [hold, ...holds.value]
      setSuccess(t('legalHolds.messages.created'))
    } catch (err) {
      setError(err, t('legalHolds.errors.createFailed'))
    } finally {
      saving.value = false
    }
  }

  async function previewScope() {
    saving.value = true
    try {
      preview.value = await previewLegalHold({
        target_user_id: draft.target_user_id.trim(),
        scope_type: 'query_scope',
        scope_query: JSON.parse(scopeQueryText.value)
      })
      setSuccess(t('legalHolds.messages.previewed'))
    } catch (err) {
      setError(err, t('legalHolds.errors.previewFailed'))
    } finally {
      saving.value = false
    }
  }

  async function transition(id: string, action: LegalHoldAction) {
    if (requiresSafetyConfirm(action) && !window.confirm(t('legalHolds.confirmAction', { action }))) return
    saving.value = true
    try {
      await transitionLegalHold(id, action)
      await loadHolds()
      setSuccess(t('legalHolds.messages.transitioned'))
    } catch (err) {
      setError(err, t('legalHolds.errors.transitionFailed'))
    } finally {
      saving.value = false
    }
  }

  function toggleSelect(id: string) {
    const next = new Set(selectedIds.value)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    selectedIds.value = next
  }

  async function bulkApprove() {
    const ids = selectedPendingIDs(holds.value, selectedIds.value)
    if (ids.length === 0) {
      setError(new Error('none'), t('legalHolds.errors.noPendingSelected'))
      return
    }
    saving.value = true
    try {
      bulkResult.value = await bulkApproveLegalHolds(ids)
      await loadHolds()
      setSuccess(t('legalHolds.messages.bulkDone', { success: bulkResult.value.success_count, failures: bulkResult.value.failure_count }))
    } catch (err) {
      setError(err, t('legalHolds.errors.transitionFailed'))
    } finally {
      saving.value = false
    }
  }

  async function bulkReject() {
    const ids = selectedPendingIDs(holds.value, selectedIds.value)
    if (ids.length === 0) {
      setError(new Error('none'), t('legalHolds.errors.noPendingSelected'))
      return
    }
    saving.value = true
    try {
      bulkResult.value = await bulkRejectLegalHolds(ids)
      await loadHolds()
      setSuccess(t('legalHolds.messages.bulkDone', { success: bulkResult.value.success_count, failures: bulkResult.value.failure_count }))
    } catch (err) {
      setError(err, t('legalHolds.errors.transitionFailed'))
    } finally {
      saving.value = false
    }
  }

  async function loadPendingSLA() {
    try {
      pendingSLA.value = await getPendingLegalHoldSLA(slaThresholdHours.value)
    } catch (err) {
      setError(err, t('legalHolds.errors.slaFailed'))
    }
  }

  return {
    holds, selectedIds, preview, pendingSLA, bulkResult, error, success, loading, saving,
    slaThresholdHours, scopeQueryText, draft, statusCounts,
    loadHolds, createHold, previewScope, transition, toggleSelect, bulkApprove, bulkReject, loadPendingSLA
  }
}
