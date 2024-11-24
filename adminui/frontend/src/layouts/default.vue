<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'

import { useAuthStore } from '@/stores/auth'
import { useInstanceDetailsStore } from '@/stores/serverInfo'

import { Icons } from '@/util/icons'

const authStore = useAuthStore()

const { loggedInUser } = storeToRefs(authStore)

const info = useInstanceDetailsStore()
info.load(false)

const router = useRouter()
const route = useRoute()

const pageLinks = [{ name: 'Dashboard', icon: Icons.Dashboard, to: '/dashboard' }]

const clusterLinks = [
  { name: 'Events', icon: Icons.Events, to: '/cluster/events' },
  { name: 'Members', icon: Icons.ClusterMembers, to: '/cluster/members' }
]

const policyLinks = [
  { name: 'Rules', icon: Icons.Edit, to: '/policy/rules' },
  { name: 'Groups', icon: Icons.Groups, to: '/policy/groups' }
]

const managementLinks = [
  { name: 'Registration Tokens', icon: Icons.RegistrationKey, to: '/management/registration_tokens' },
  { name: 'Users', icon: Icons.Groups, to: '/management/users' },
  { name: 'Devices', icon: Icons.Device, to: '/management/devices' }
]

const adminPageLinks = [
  { name: 'Settings', icon: Icons.Config, to: '/settings' },
  { name: 'Admin Users', icon: Icons.User, to: '/admin_users' }
]

const debugPageLinks = [
  { name: 'Wireguard Peers', icon: Icons.Peers, to: '/diagnostics/wg' },
  { name: 'Firewall State', icon: Icons.FirewallState, to: '/diagnostics/firewall' },
  { name: 'Test Rule', icon: Icons.Test, to: '/diagnostics/check' },
  { name: 'User ACLs', icon: Icons.List, to: '/diagnostics/acls' },
  { name: 'Notifications', icon: Icons.Send, to: '/diagnostics/notifications' }

]

async function logout() {
  await authStore.logout()
  router.push('/login')
}
</script>

<template>
  <div class="drawer lg:drawer-open bg-slate-100">
    <input id="my-drawer" name="my-drawer" type="checkbox" class="drawer-toggle" />
    <div class="drawer-content h-max">
      <router-view />

      <label for="my-drawer" class="fixed btn text-neutral-content bg-neutral lg:hidden">
        <span class="w-6 text-center"><font-awesome-icon :icon="Icons.Open" /></span>
      </label>
    </div>
    <div class="drawer-side">
      <label for="my-drawer" aria-label="close sidebar" class="drawer-overlay"></label>
      <aside class="flex min-h-full w-72 flex-col p-4 bg-neutral text-neutral-content">
        <RouterLink to="/dashboard">
          <h2 class="btn btn-ghost w-full text-center text-3xl">Wag</h2>
          <div class="w-full text-center" v-if="info.serverInfo.version != ''">
            <small class="text-center font-mono text-xs">{{ info.serverInfo.version }}</small>
          </div>
        </RouterLink>
        <hr class="mt-4 h-px border-0 bg-gray-700" />

        <ul class="menu">
          <li v-for="link in pageLinks" :key="link.name" :class="route.path == link.to ? 'bordered' : 'hover-bordered'">
            <RouterLink :to="link.to" :class="route.path == link.to ? 'active' : ''">
              <span class="w-6 text-center"><font-awesome-icon :icon="link.icon" /></span>

              {{ link.name }}
            </RouterLink>
          </li>
        </ul>

        <hr class="mt-4 h-px border-0 bg-gray-700" />
        <ul class="menu">
          <li v-for="link in clusterLinks" :key="link.name" :class="route.path == link.to ? 'bordered' : 'hover-bordered'">
            <RouterLink :to="link.to" :class="route.path == link.to ? 'active' : ''">
              <span class="w-6 text-center"><font-awesome-icon :icon="link.icon" /></span>

              {{ link.name }}
            </RouterLink>
          </li>
        </ul>

        <hr class="mt-4 h-px border-0 bg-gray-700" />

        <ul class="menu">
          <li v-for="link in policyLinks" :key="link.name" :class="route.path == link.to ? 'bordered' : 'hover-bordered'">
            <RouterLink :to="link.to" :class="route.path == link.to ? 'active' : ''">
              <span class="w-6 text-center"><font-awesome-icon :icon="link.icon" /></span>

              {{ link.name }}
            </RouterLink>
          </li>
        </ul>

        <hr class="mt-4 h-px border-0 bg-gray-700" />

        <ul class="menu">
          <li v-for="link in managementLinks" :key="link.name" :class="route.path == link.to ? 'bordered' : 'hover-bordered'">
            <RouterLink :to="link.to" :class="route.path == link.to ? 'active' : ''">
              <span class="w-6 text-center"><font-awesome-icon :icon="link.icon" /></span>

              {{ link.name }}
            </RouterLink>
          </li>
        </ul>

        <hr class="mt-4 h-px border-0 bg-gray-700" />

        <ul class="menu">
          <li v-for="link in adminPageLinks" :key="link.name" :class="route.path == link.to ? 'bordered' : 'hover-bordered'">
            <RouterLink :to="link.to" :class="route.path == link.to ? 'active' : ''">
              <span class="w-6 text-center"><font-awesome-icon :icon="link.icon" /></span>
              {{ link.name }}
            </RouterLink>
          </li>
        </ul>

        <hr class="mt-4 h-px border-0 bg-gray-700" />

        <ul class="menu justify-self-end">
          <li class="hover-bordered" :class="route.path == '/diag' ? 'bordered' : 'hover-bordered'">
            <div class="text-content-neutral dropdown dropdown-top">
              <label tabindex="0" class="col-span-2 w-full cursor-pointer">
                <span class="w-6 text-center"><font-awesome-icon :icon="['fa-solid', 'circle-nodes']" /></span>
                <span>Advanced</span>
              </label>

              <ul tabindex="0" class="menu dropdown-content rounded-box w-52 bg-base-100 p-2 pb-4 text-black shadow">
                <li v-for="link in debugPageLinks" :key="link.name" :class="route.path == link.to ? 'bordered' : 'hover-bordered'">
                  <RouterLink :to="link.to">
                    <span class="w-6 text-center"><font-awesome-icon :icon="link.icon" /></span>
                    {{ link.name }}
                  </RouterLink>
                </li>
              </ul>
            </div>
          </li>
        </ul>

        <div class="flex flex-grow"></div>

        <ul class="menu justify-self-end">
          <li class="hover-bordered" :class="route.path == '/account' ? 'bordered' : 'hover-bordered'">
            <div class="text-content-neutral dropdown dropdown-top">
              <label tabindex="0" class="col-span-2 w-full cursor-pointer">
                <span class="w-6 text-center"><font-awesome-icon :icon="Icons.User" /></span>
                <span
                  >Welcome, <strong>{{ loggedInUser?.username }}</strong></span
                >
              </label>

              <ul tabindex="0" class="menu dropdown-content rounded-box w-52 bg-base-100 p-2 pb-4 text-black shadow">
                <li :class="route.path == '/account' ? 'bordered' : 'hover-bordered'">
                  <RouterLink to="/account">
                    <span><font-awesome-icon :icon="Icons.User" /></span>
                    <span>My account</span>
                  </RouterLink>
                </li>
                <li>
                  <a @click="logout()">
                    <span><font-awesome-icon :icon="Icons.SignOut" /></span>
                    <span>Sign out</span>
                  </a>
                </li>
              </ul>
            </div>
          </li>
        </ul>
      </aside>
    </div>
  </div>
</template>

<style scoped>
/* Backported from Daisy UI v2 */
.menu li {
  margin-top: 0.65rem;
  transition: border 0.125s ease;
}

.menu li a {
  padding: 0.6rem 1.25rem;
}

.menu {
  font-size: 1rem;
}

.menu li.hover-bordered {
  @apply border-l-4 border-transparent hover:border-primary;
}

.menu li.hover-bordered:hover {
  background: rgba(255, 255, 255, 0.1);
}

.menu li.bordered {
  @apply border-l-4 border-primary;
}

.dropdown,
.dropdown label,
.dropdown label:hover,
.dropdown label:active {
  color: inherit !important;
}

.menu .dropdown {
  padding: 0.6rem 1.25rem;
}

/* Same as a menu item */
.menu .dropdown label {
  display: grid;
  grid-auto-flow: column;
  align-content: flex-start;
  align-items: center;
  gap: 0.5rem;
  grid-auto-columns: max-content auto max-content;
}

.menu li:hover a,
.menu li a:active {
  color: inherit;
}

.tooltip-white-bg::before,
.tooltip-white-bg::after {
  --tooltip-color: white;
}
</style>
