import { reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { listAdminEvents, type AdminEvent } from '../api/legal'

export function useAdminEvents() {
  const { t } = useI18n()
  const events = ref<AdminEvent[]>([])
  const total = ref(0)
  const loading = ref(false)
  const error = ref('')
  const offset = ref(0)
  const limit = 50
  const filters = reactive({ actor_user_id: '', resource: '', action: '', org: '', success: '' })

  async function load() {
    loading.value = true
    error.value = ''
    try {
      const data = await listAdminEvents({
        actor_user_id: filters.actor_user_id || undefined,
        resource: filters.resource || undefined,
        action: filters.action || undefined,
        limit,
        offset: offset.value
      })
      events.value = data.data
      total.value = data.total
    } catch (err) {
      const anyErr = err as { response?: { data?: { error?: string } } }
      error.value = anyErr.response?.data?.error || t('adminEvents.loadFailed')
    } finally {
      loading.value = false
    }
  }

  function nextPage() {
    if (offset.value + limit >= total.value) return
    offset.value += limit
    load()
  }

  function prevPage() {
    offset.value = Math.max(0, offset.value - limit)
    load()
  }

  return { events, total, loading, error, offset, limit, filters, load, nextPage, prevPage }
}
