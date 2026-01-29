<template>
  <div>
    <h2 class="text-2xl font-bold mb-6">Users</h2>
    <div class="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-dark-700 text-left text-gray-500">
            <th class="px-4 py-3">Email</th>
            <th class="px-4 py-3">Role</th>
            <th class="px-4 py-3">Status</th>
            <th class="px-4 py-3">Created</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="user in users" :key="user.id" class="border-b border-dark-800 hover:bg-dark-800/50">
            <td class="px-4 py-3">{{ user.email }}</td>
            <td class="px-4 py-3">
              <span class="px-2 py-0.5 rounded text-xs font-medium" :class="user.role === 'admin' ? 'bg-purple-900/50 text-purple-400' : 'bg-dark-700 text-gray-400'">
                {{ user.role }}
              </span>
            </td>
            <td class="px-4 py-3">
              <span :class="user.is_active ? 'text-green-400' : 'text-red-400'">{{ user.is_active ? 'Active' : 'Inactive' }}</span>
            </td>
            <td class="px-4 py-3 text-gray-500">{{ new Date(user.created_at).toLocaleDateString() }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api from '../api/client'

const users = ref<any[]>([])

onMounted(async () => {
  const { data } = await api.get('/users')
  users.value = data
})
</script>
