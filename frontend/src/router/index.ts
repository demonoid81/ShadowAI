import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      component: () => import('../pages/LoginPage.vue'),
      meta: { public: true }
    },
    {
      path: '/register',
      component: () => import('../pages/RegisterPage.vue'),
      meta: { public: true }
    },
    {
      path: '/',
      component: () => import('../layouts/DashboardLayout.vue'),
      children: [
        { path: '', redirect: '/dashboard' },
        { path: 'dashboard', component: () => import('../pages/DashboardPage.vue') },
        { path: 'audit', component: () => import('../pages/AuditLogPage.vue') },
        { path: 'policies', component: () => import('../pages/PoliciesPage.vue') },
        { path: 'budget', component: () => import('../pages/BudgetPage.vue') },
        { path: 'tenants', component: () => import('../pages/TenantsPage.vue') },
        { path: 'users', component: () => import('../pages/UsersPage.vue') },
        { path: 'providers', component: () => import('../pages/ProvidersPage.vue') },
        { path: 'firewall', component: () => import('../pages/FirewallPage.vue') },
        { path: 'evidence', component: () => import('../pages/EvidencePage.vue') },
        { path: 'compliance', component: () => import('../pages/CompliancePage.vue') },
        { path: 'operations', component: () => import('../pages/OperationsPage.vue') },
        { path: 'settings', component: () => import('../pages/SettingsPage.vue') },
        { path: 'internal-db', component: () => import('../pages/InternalDbPage.vue') }
      ]
    }
  ]
})

router.beforeEach((to) => {
  const token = localStorage.getItem('token')
  if (!to.meta.public && !token) return '/login'
})

export default router
