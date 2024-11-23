import { createRouter, createWebHistory } from 'vue-router'

import DefaultLayout from '@/layouts/default.vue'

function withDefaultLayout(component: () => any, name: string) {
  return {
    component: DefaultLayout,
    children: [{ path: '', name: `${name} Layout`, component }]
  }
}

function route(path: string, name: string, component: () => any) {
  return {
    path,
    name,
    ...withDefaultLayout(component, name)
  }
}

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('@/pages/Login.vue')
    },
    {
      path: '/',
      name: 'login-home',
      component: () => import('@/pages/Login.vue')
    },
    // {
    //   path: '/login/oidc',
    //   name: 'oidc-callback',
    //   component: () => import('@/pages/LoginOIDCCallback.vue')
    // },
    route('/dashboard', 'Dashboard', () => import('@/pages/Dashboard.vue')),
    route('/account', 'My Account', () => import('@/pages/Account.vue')),

    route('/cluster/events', 'Cluster Events', () => import('@/pages/ClusterEvents.vue')),
    route('/cluster/members', 'Cluster Members', () => import('@/pages/ClusterMembers.vue')),

    route('/policy/rules', 'Firewall Rules', () => import('@/pages/Rules.vue')),
    route('/policy/groups', 'Groups', () => import('@/pages/Groups.vue')),

    route('/diagnostics/wg', 'Wireguard Diagnostics', () => import('@/pages/Diagnostics/WireguardPeers.vue')),
    route('/diagnostics/firewall', 'Firewall Diagnostics', () => import('@/pages/Diagnostics/FirewallState.vue')),
    route('/diagnostics/check', 'Check Firewall', () => import('@/pages/Diagnostics/TestRule.vue')),
    // route('/diagnostics/acls', 'ACLs', () => import('@/pages/projects/project.vue')),

    route('/management/users', 'User Management', () => import('@/pages/Users.vue')),
    route('/management/devices', 'Device Management', () => import('@/pages/Devices.vue')),
    route('/management/registration_tokens', 'Registration Tokens', () => import('@/pages/RegistrationTokens.vue')),

    route('/settings', 'Settings', () => import('@/pages/Settings.vue')),
    route('/admin_users', 'Admin Users', () => import('@/pages/AdminUsers.vue'))
  ]
})

export default router
