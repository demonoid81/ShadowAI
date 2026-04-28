import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  createOrganization,
  createSCIMToken,
  getOrgBudget,
  getOrganization,
  listOrganizations,
  listSCIMTokens,
  revokeSCIMToken,
  updateOrgBudget,
  updateOrganization,
  type OrgBudgetStatus,
  type Organization,
  type SCIMToken
} from '../api/tenants'
import { useAuthStore } from '../stores/auth'
import { canManageAllOrgs, canManageOwnOrg, centsToDollars, dollarsToCents } from '../utils/tenantUi'

export function useTenantAdmin() {
  const { t } = useI18n()
  const auth = useAuthStore()

  const orgs = ref<Organization[]>([])
  const selectedOrgID = ref('')
  const scimTokens = ref<SCIMToken[]>([])
  const budgetStatus = ref<OrgBudgetStatus | null>(null)
  const error = ref('')
  const success = ref('')
  const plainToken = ref('')
  const newTokenLabel = ref('')
  const showCreate = ref(false)

  const loadingOrgs = ref(false)
  const loadingTokens = ref(false)
  const loadingBudget = ref(false)
  const savingOrg = ref(false)
  const savingToken = ref(false)
  const savingBudget = ref(false)

  const createDraft = reactive({ name: '', slug: '' })
  const editDraft = reactive({ name: '', slug: '', is_active: true })
  const budgetLimitDollars = ref('0.00')
  const budgetMode = ref<'disabled' | 'observe' | 'enforce'>('disabled')

  const isGlobalAdmin = computed(() => canManageAllOrgs(auth.role))
  const canManageTenants = computed(() => canManageOwnOrg(auth.role))
  const ownOrgID = computed(() => auth.claims?.org_id ?? '')
  const selectedOrg = computed(() => orgs.value.find(org => org.id === selectedOrgID.value) ?? null)
  const canEditSelectedOrg = computed(() => isGlobalAdmin.value || selectedOrgID.value === ownOrgID.value)

  function setMessage(kind: 'error' | 'success', message: string) {
    if (kind === 'error') {
      error.value = message
      success.value = ''
    } else {
      success.value = message
      error.value = ''
    }
  }

  function apiError(err: unknown, fallbackKey: string) {
    const anyErr = err as { response?: { data?: { error?: string }, status?: number } }
    const status = anyErr.response?.status
    const backendMessage = anyErr.response?.data?.error
    if (status === 403) return t('tenants.errors.forbidden')
    if (status === 404) return t('tenants.errors.notFound')
    if (status === 409) return t('tenants.errors.conflict')
    return backendMessage || t(fallbackKey)
  }

  function syncEditDraft(org: Organization | null) {
    editDraft.name = org?.name ?? ''
    editDraft.slug = org?.slug ?? ''
    editDraft.is_active = org?.is_active ?? true
  }

  async function loadOrgs() {
    if (!canManageTenants.value) return
    loadingOrgs.value = true
    try {
      if (isGlobalAdmin.value) {
        orgs.value = await listOrganizations()
      } else if (ownOrgID.value) {
        orgs.value = [await getOrganization(ownOrgID.value)]
      } else {
        orgs.value = []
        setMessage('error', t('tenants.errors.missingOrg'))
      }
      if (!selectedOrgID.value && orgs.value.length > 0) await selectOrg(orgs.value[0].id)
    } catch (err) {
      setMessage('error', apiError(err, 'tenants.errors.loadFailed'))
    } finally {
      loadingOrgs.value = false
    }
  }

  async function selectOrg(orgID: string) {
    selectedOrgID.value = orgID
    plainToken.value = ''
    syncEditDraft(selectedOrg.value)
    await Promise.all([loadTokens(orgID), loadBudget(orgID)])
  }

  async function createOrg() {
    if (!isGlobalAdmin.value) return
    savingOrg.value = true
    try {
      const org = await createOrganization({ name: createDraft.name.trim(), slug: createDraft.slug.trim() })
      orgs.value = [org, ...orgs.value]
      createDraft.name = ''
      createDraft.slug = ''
      showCreate.value = false
      setMessage('success', t('tenants.messages.orgCreated'))
      await selectOrg(org.id)
    } catch (err) {
      setMessage('error', apiError(err, 'tenants.errors.saveFailed'))
    } finally {
      savingOrg.value = false
    }
  }

  async function saveOrg() {
    if (!selectedOrgID.value || !canEditSelectedOrg.value) return
    savingOrg.value = true
    try {
      const updated = await updateOrganization(selectedOrgID.value, { ...editDraft })
      orgs.value = orgs.value.map(org => org.id === updated.id ? updated : org)
      syncEditDraft(updated)
      setMessage('success', t('tenants.messages.orgSaved'))
    } catch (err) {
      setMessage('error', apiError(err, 'tenants.errors.saveFailed'))
    } finally {
      savingOrg.value = false
    }
  }

  async function loadTokens(orgID: string) {
    loadingTokens.value = true
    try {
      scimTokens.value = await listSCIMTokens(orgID)
    } catch (err) {
      scimTokens.value = []
      setMessage('error', apiError(err, 'tenants.errors.tokensFailed'))
    } finally {
      loadingTokens.value = false
    }
  }

  async function createToken() {
    if (!selectedOrgID.value) return
    savingToken.value = true
    try {
      const result = await createSCIMToken(selectedOrgID.value, newTokenLabel.value.trim())
      scimTokens.value = [result.token, ...scimTokens.value]
      plainToken.value = result.plain_token
      newTokenLabel.value = ''
      setMessage('success', t('tenants.messages.tokenCreated'))
    } catch (err) {
      setMessage('error', apiError(err, 'tenants.errors.tokenCreateFailed'))
    } finally {
      savingToken.value = false
    }
  }

  async function revokeToken(tokenID: string) {
    if (!selectedOrgID.value || !window.confirm(t('tenants.scim.revokeConfirm'))) return
    try {
      await revokeSCIMToken(selectedOrgID.value, tokenID)
      scimTokens.value = scimTokens.value.filter(token => token.id !== tokenID)
      setMessage('success', t('tenants.messages.tokenRevoked'))
    } catch (err) {
      setMessage('error', apiError(err, 'tenants.errors.tokenRevokeFailed'))
    }
  }

  async function loadBudget(orgID: string) {
    loadingBudget.value = true
    try {
      budgetStatus.value = await getOrgBudget(orgID)
      budgetLimitDollars.value = centsToDollars(budgetStatus.value.policy.monthly_limit_cents)
      budgetMode.value = budgetStatus.value.policy.mode
    } catch (err) {
      budgetStatus.value = null
      setMessage('error', apiError(err, 'tenants.errors.budgetFailed'))
    } finally {
      loadingBudget.value = false
    }
  }

  async function saveBudget() {
    if (!selectedOrgID.value) return
    savingBudget.value = true
    try {
      await updateOrgBudget(selectedOrgID.value, {
        monthly_limit_cents: dollarsToCents(budgetLimitDollars.value),
        mode: budgetMode.value
      })
      await loadBudget(selectedOrgID.value)
      setMessage('success', t('tenants.messages.budgetSaved'))
    } catch (err) {
      setMessage('error', apiError(err, 'tenants.errors.budgetSaveFailed'))
    } finally {
      savingBudget.value = false
    }
  }

  return {
    orgs, selectedOrgID, scimTokens, budgetStatus, error, success, plainToken, newTokenLabel, showCreate,
    loadingOrgs, loadingTokens, loadingBudget, savingOrg, savingToken, savingBudget,
    createDraft, editDraft, budgetLimitDollars, budgetMode,
    isGlobalAdmin, canManageTenants, selectedOrg, canEditSelectedOrg,
    loadOrgs, selectOrg, createOrg, saveOrg, createToken, revokeToken, saveBudget
  }
}
