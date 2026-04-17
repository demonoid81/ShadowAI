<template>
  <span v-if="!rawJson" class="text-gray-600">—</span>
  <button v-else-if="parseError" type="button"
    class="px-2 py-0.5 rounded text-xs bg-red-900/40 text-red-400 font-mono"
    :title="$t('audit.shadowInvalid')"
    @click="$emit('open')">
    {{ $t('audit.shadowInvalid') }}
  </button>
  <button v-else type="button"
    class="px-2 py-0.5 rounded text-xs bg-yellow-900/40 text-yellow-400 font-mono hover:bg-yellow-900/60"
    @click="$emit('open')">
    {{ $t('audit.shadowCount', { n: count }) }}
  </button>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  rawJson?: string | null
}>()
defineEmits<{ open: [] }>()

// Отдельный ShadowCell (а не inline в RequestTable) изолирует парсинг:
// если backend вдруг пришлёт malformed JSON, одна строка показывает
// "invalid shadow payload", а не ломает весь рендер таблицы.
interface ParseResult {
  count: number
  parseError: boolean
}

const result = computed<ParseResult>(() => {
  if (!props.rawJson) return { count: 0, parseError: false }
  try {
    const v = JSON.parse(props.rawJson)
    if (!Array.isArray(v)) return { count: 0, parseError: true }
    return { count: v.length, parseError: false }
  } catch {
    return { count: 0, parseError: true }
  }
})

const count = computed(() => result.value.count)
const parseError = computed(() => result.value.parseError)
</script>
