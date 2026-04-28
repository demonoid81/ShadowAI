<template>
  <div class="space-y-8">
    <section class="hero-panel">
      <div class="relative z-10 max-w-5xl">
        <div class="mb-5 flex flex-wrap gap-2">
          <span v-for="tag in tags" :key="tag" class="tag-chip">{{ $t(tag) }}</span>
        </div>
        <h2 class="text-4xl font-semibold tracking-tight text-white sm:text-5xl">
          {{ $t('tenants.title') }}
        </h2>
        <p class="mt-5 max-w-3xl text-base leading-7 text-slate-300">
          {{ $t('tenants.subtitle') }}
        </p>
      </div>
    </section>

    <section v-if="!canManageTenants" class="console-card border-amber-200/20 bg-amber-200/10">
      <div class="section-kicker text-amber-100/70">{{ $t('tenants.manage.accessKicker') }}</div>
      <h3 class="section-title text-amber-50">{{ $t('tenants.manage.accessTitle') }}</h3>
      <p class="mt-3 text-sm leading-6 text-amber-100/80">{{ $t('tenants.manage.accessBody') }}</p>
    </section>

    <template v-else>
      <div v-if="error" class="rounded-3xl border border-red-300/20 bg-red-400/10 p-4 text-sm text-red-100">
        {{ error }}
      </div>
      <div v-if="success" class="rounded-3xl border border-emerald-300/20 bg-emerald-400/10 p-4 text-sm text-emerald-100">
        {{ success }}
      </div>

      <section class="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
        <OrgListPanel
          :draft="createDraft"
          :orgs="orgs"
          :selected-org-id="selectedOrgID"
          :loading="loadingOrgs"
          :can-create="isGlobalAdmin"
          :show-create="showCreate"
          @select="selectOrg"
          @toggle-create="showCreate = !showCreate"
          @update:draft="Object.assign(createDraft, $event)"
          @create="createOrg"
        />

        <OrgDetailPanel
          :draft="editDraft"
          :org="selectedOrg"
          :can-edit="canEditSelectedOrg"
          :saving="savingOrg"
          @update:draft="Object.assign(editDraft, $event)"
          @save-org="saveOrg"
        />
      </section>

      <section v-if="selectedOrgID" class="grid gap-6 xl:grid-cols-2">
        <SCIMTokenPanel
          v-model:label="newTokenLabel"
          :org-id="selectedOrgID"
          :tokens="scimTokens"
          :plain-token="plainToken"
          :loading="loadingTokens"
          :saving="savingToken"
          @create-token="createToken"
          @revoke-token="revokeToken"
          @clear-plain="plainToken = ''"
        />

        <OrgBudgetPanel
          v-model:limit-dollars="budgetLimitDollars"
          v-model:mode="budgetMode"
          :status="budgetStatus"
          :loading="loadingBudget"
          :saving="savingBudget"
          @save-budget="saveBudget"
        />
      </section>
    </template>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import OrgBudgetPanel from '../components/tenants/OrgBudgetPanel.vue'
import OrgDetailPanel from '../components/tenants/OrgDetailPanel.vue'
import OrgListPanel from '../components/tenants/OrgListPanel.vue'
import SCIMTokenPanel from '../components/tenants/SCIMTokenPanel.vue'
import { useTenantAdmin } from '../composables/useTenantAdmin'

const tags = ['tenants.tags.org', 'tenants.tags.scim', 'tenants.tags.globalAdmin', 'tenants.tags.budget']

const {
  orgs, selectedOrgID, scimTokens, budgetStatus, error, success, plainToken, newTokenLabel, showCreate,
  loadingOrgs, loadingTokens, loadingBudget, savingOrg, savingToken, savingBudget,
  createDraft, editDraft, budgetLimitDollars, budgetMode,
  isGlobalAdmin, canManageTenants, selectedOrg, canEditSelectedOrg,
  loadOrgs, selectOrg, createOrg, saveOrg, createToken, revokeToken, saveBudget
} = useTenantAdmin()

onMounted(loadOrgs)
</script>
