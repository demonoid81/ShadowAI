<template>
  <div>
    <div class="flex justify-between items-center mb-6">
      <h2 class="text-2xl font-bold">{{ $t('users.title') }}</h2>
      <button @click="showAdd = !showAdd"
        class="px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-sm transition-colors">
        {{ showAdd ? $t('policies.cancel') : $t('users.addUser') }}
      </button>
    </div>

    <!-- Add User Form -->
    <div v-if="showAdd" class="bg-dark-900 border border-dark-700 rounded-xl p-6 mb-6">
      <form @submit.prevent="addUser" class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <input v-model="newUser.email" type="email" required :placeholder="$t('users.email')"
          class="px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 focus:border-primary-500 focus:outline-none" />
        <input v-model="newUser.password" type="password" required :placeholder="$t('auth.password')"
          class="px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100 focus:border-primary-500 focus:outline-none" />
        <div class="flex gap-2">
          <select v-model="newUser.role"
            class="flex-1 px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-gray-100">
            <option value="user">{{ $t('users.user') }}</option>
            <option value="analyst">{{ $t('users.analyst') }}</option>
            <option value="auditor">{{ $t('users.auditor') }}</option>
            <option value="admin">{{ $t('users.admin') }}</option>
          </select>
          <button type="submit" class="px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-sm">
            {{ $t('users.addUser') }}
          </button>
        </div>
      </form>
    </div>

    <!-- Users Table -->
    <div class="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-dark-700 text-left text-gray-500">
            <th class="px-4 py-3">{{ $t('users.email') }}</th>
            <th class="px-4 py-3">{{ $t('users.role') }}</th>
            <th class="px-4 py-3">{{ $t('users.status') }}</th>
            <th class="px-4 py-3">{{ $t('users.created') }}</th>
            <th class="px-4 py-3"></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="user in users" :key="user.id" class="border-b border-dark-800 hover:bg-dark-800/50">
            <td class="px-4 py-3">{{ user.email }}</td>
            <td class="px-4 py-3">
              <select v-if="editing === user.id" v-model="user.role"
                class="px-2 py-1 bg-dark-800 border border-dark-700 rounded text-xs text-gray-100">
                <option value="admin">{{ $t('users.admin') }}</option>
                <option value="user">{{ $t('users.user') }}</option>
                <option value="analyst">{{ $t('users.analyst') }}</option>
                <option value="auditor">{{ $t('users.auditor') }}</option>
              </select>
              <span v-else class="px-2 py-0.5 rounded text-xs font-medium"
                :class="user.role === 'admin' ? 'bg-purple-900/50 text-purple-400' : 'bg-dark-700 text-gray-400'">
                {{ user.role }}
              </span>
            </td>
            <td class="px-4 py-3">
              <span :class="user.is_active ? 'text-green-400' : 'text-red-400'">
                {{ user.is_active ? $t('users.active') : $t('users.inactive') }}
              </span>
            </td>
            <td class="px-4 py-3 text-gray-500">{{ new Date(user.created_at).toLocaleDateString() }}</td>
            <td class="px-4 py-3 flex gap-2">
              <template v-if="editing === user.id">
                <button @click="saveUser(user)"
                  class="px-3 py-1 text-green-400 hover:bg-green-900/30 rounded text-xs">{{ $t('users.save') }}</button>
                <button @click="editing = ''"
                  class="px-3 py-1 text-gray-400 hover:bg-dark-700 rounded text-xs">{{ $t('policies.cancel') }}</button>
              </template>
              <template v-else>
                <button @click="editing = user.id"
                  class="px-3 py-1 text-primary-400 hover:bg-primary-900/30 rounded text-xs">{{ $t('users.edit') }}</button>
                <button @click="toggleActive(user)"
                  class="px-3 py-1 rounded text-xs"
                  :class="user.is_active ? 'text-red-400 hover:bg-red-900/30' : 'text-green-400 hover:bg-green-900/30'">
                  {{ user.is_active ? $t('users.deactivate') : $t('users.activate') }}
                </button>
              </template>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '../api/client'

const { t } = useI18n()
const users = ref<any[]>([])
const editing = ref('')
const showAdd = ref(false)
const newUser = reactive({ email: '', password: '', role: 'user' })

async function fetchUsers() {
  const { data } = await api.get('/users')
  users.value = data
}

async function addUser() {
  await api.post('/auth/register', newUser)
  showAdd.value = false
  newUser.email = ''
  newUser.password = ''
  newUser.role = 'user'
  fetchUsers()
}

async function saveUser(user: any) {
  await api.put(`/users/${user.id}`, { role: user.role })
  editing.value = ''
  fetchUsers()
}

async function toggleActive(user: any) {
  await api.put(`/users/${user.id}`, { is_active: !user.is_active })
  fetchUsers()
}

onMounted(fetchUsers)
</script>
