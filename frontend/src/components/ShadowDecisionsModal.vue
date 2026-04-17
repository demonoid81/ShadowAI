<template>
  <Teleport to="body">
    <div v-if="open" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      @click.self="$emit('close')">
      <div class="bg-dark-900 border border-dark-700 rounded-xl w-full max-w-2xl max-h-[80vh] flex flex-col">
        <div class="flex items-center justify-between px-6 py-4 border-b border-dark-700">
          <h3 class="text-lg font-semibold">{{ $t('audit.shadowModalTitle') }}</h3>
          <button @click="$emit('close')" class="text-gray-500 hover:text-gray-300 text-xl leading-none">&times;</button>
        </div>
        <div class="flex-1 overflow-auto p-6">
          <div v-if="parseError" class="text-red-400 text-sm">
            {{ $t('audit.shadowInvalid') }}
            <pre class="mt-2 text-xs text-gray-500 whitespace-pre-wrap break-all">{{ rawJson }}</pre>
          </div>
          <div v-else-if="!parsed || parsed.length === 0" class="text-gray-500 text-sm">
            {{ $t('audit.shadowModalEmpty') }}
          </div>
          <pre v-else class="text-sm font-mono text-gray-200 whitespace-pre-wrap break-all">{{ pretty }}</pre>
        </div>
        <div class="px-6 py-3 border-t border-dark-700 flex justify-end">
          <button @click="$emit('close')" class="px-3 py-1 bg-dark-700 rounded text-sm">
            {{ $t('common.close') }}
          </button>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  open: boolean
  /** Raw JSON-string from audit_logs.shadow_decisions_json. Может быть null/undefined/пустым. */
  rawJson?: string | null
}>()
defineEmits<{ close: [] }>()

// Параллельно держим parseError и parsed, чтобы template мог различить
// три состояния: невалидный JSON (показываем raw + предупреждение),
// пустой массив (отдельный empty-state), и валидный массив (pretty-print).
interface ParsedState {
  parsed: unknown[] | null
  parseError: boolean
}

const state = computed<ParsedState>(() => {
  if (!props.rawJson) return { parsed: [], parseError: false }
  try {
    const v = JSON.parse(props.rawJson)
    if (!Array.isArray(v)) return { parsed: null, parseError: true }
    return { parsed: v, parseError: false }
  } catch {
    return { parsed: null, parseError: true }
  }
})

const parsed = computed(() => state.value.parsed)
const parseError = computed(() => state.value.parseError)
const pretty = computed(() => {
  if (!parsed.value) return ''
  return JSON.stringify(parsed.value, null, 2)
})
</script>
