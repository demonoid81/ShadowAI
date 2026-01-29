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
      path: '/',
      component: () => import('../layouts/DashboardLayout.vue'),
      children: [
        { path: '', redirect: '/dashboard' },
        { path: 'dashboard', component: () => import('../pages/DashboardPage.vue') },
        { path: 'audit', component: () => import('../pages/AuditLogPage.vue') },
        { path: 'policies', component: () => import('../pages/PoliciesPage.vue') },
        { path: 'budget', component: () => import('../pages/BudgetPage.vue') },
        { path: 'users', component: () => import('../pages/UsersPage.vue') }
      ]
    }
  ]
})

router.beforeEach((to) => {
  const token = localStorage.getItem('token')
  if (!to.meta.public && !token) return '/login'
})

export default router
