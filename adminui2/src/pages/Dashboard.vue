<script setup lang="ts">
import { computed } from 'vue'
import EmptyTable from '@/components/EmptyTable.vue'

import { useUsersStore } from '@/stores/users'
import { useDevicesStore } from '@/stores/devices'
import { useTokensStore } from '@/stores/registration_tokens'
import { useInstanceDetailsStore } from '@/stores/serverInfo'

const devicesStore = useDevicesStore()
devicesStore.load(false)

const registrationTokensStore = useTokensStore()
registrationTokensStore.load(false)

const instanceDetails = useInstanceDetailsStore()
instanceDetails.load(true)

const usersStore = useUsersStore()
usersStore.load(false)

const allUsers = computed(() => usersStore.users ?? [])
const usersLackingMfa = computed(() => allUsers.value.filter((x) => (x.mfa_type == '' || x.mfa_type == 'unset') ))

const allDevices = computed(() => devicesStore.devices ?? [])
const lockedDevices = computed(() => allDevices.value.filter((x) => x.is_locked ))

</script>

<template>
  <main class="w-full p-4">
    <h1 class="text-4xl font-bold">Dashboard</h1>
    <div class="mt-6 flex flex-wrap gap-6">
      <div class="flex w-full gap-4">
        <div class="flex grid w-1/2 grid-cols-2 gap-4 min-w-[405px]">
          <router-link to="/management/users" class="card-compact bg-base-100 shadow-xl border-l-4" :class="usersLackingMfa.length == 0? 'border-primary' : 'border-error'">
            <div class="card-body" v-if="usersLackingMfa.length == 0">
              <h5 class="card-title">Manage Users</h5>
              <div>{{ allUsers.length == 0 ? 'No users' : allUsers.length + ' users' }}</div>
            </div>
            <div class="card-body" v-else>
              <h5 class="card-title">Manage MFA</h5>
              <div>{{ usersLackingMfa.length + " user have not completed MFA registration" }}</div>
            </div>
          </router-link>
          <router-link to="/management/devices" class="card-compact bg-base-100 shadow-xl border-l-4" :class="lockedDevices.length == 0? 'border-primary' : 'border-error'">
            <div class="card-body" v-if="lockedDevices.length == 0">
              <h5 class="card-title">Manage Devices</h5>
              <div>{{ devicesStore.numDevices() == 0 ? 'No devices' : devicesStore.numDevices() }}</div>
            </div>
            <div class="card-body" v-else>
              <h5 class="card-title">Unlock Device{{ lockedDevices.length > 1? "s" : "" }}</h5>
              <div>{{ lockedDevices.length + " locked device" + (lockedDevices.length > 1? "s" : "")}}</div>
            </div>
          </router-link>
          <router-link to="/management/devices" class="card-compact bg-base-100 shadow-xl border-l-4 border-primary">
            <div class="card-body">
              <h5 class="card-title">View Active Sessions</h5>
              <div>
                {{
                  allDevices.filter(e => {
                    e.active
                  }).length ?? 0 + ' active sessions'
                }}
              </div>
            </div>
          </router-link>
          <router-link to="/management/registration_tokens" class="card-compact bg-base-100 shadow-xl border-l-4" :class="registrationTokensStore.tokens?.length == 0 ? 'border-primary': 'border-warning'">
            <div class="card-body">
              <h5 class="card-title">Registration Tokens</h5>
              <div>
                {{ registrationTokensStore.tokens?.length == 0 ? 'No active tokens' : registrationTokensStore.tokens?.length + ' tokens' }}
              </div>
            </div>
          </router-link>
        </div>

        <div class="card w-1/2 bg-base-100 shadow-xl min-w-[380px]">
          <div class="card-body p-4">
            <h2 class="card-title">Instance Details</h2>
            <table class="table w-full table-fixed">
              <tbody>
                <tr v-for="(value, name) in instanceDetails.serverInfo" :key="name">
                  <td>
                    {{
                      name
                        .split('_')
                        .map(a => a[0].toUpperCase() + a.slice(1))
                        .join(' ')
                    }}
                  </td>
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap">
                    {{ value }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
      <div class="card w-full bg-base-100 shadow-xl min-w-[802px]">
        <div class="card-body">
          <h2 class="card-title">Recent Log Messages</h2>
          <table class="table w-full">
            <tbody>
              <tr class="hover" v-for="(line, index) in instanceDetails.log" :key="'log-line-' + index">
                <td>
                  {{ line }}
                </td>
              </tr>
            </tbody>
          </table>
          <EmptyTable v-if="instanceDetails.log.length == 0" text="No log lines yet" />
        </div>
      </div>
    </div>
  </main>
</template>

<style scoped>
thead > tr > th {
  background: none !important;
}

.first-col-bold > tr td:first-of-type {
  font-weight: bold;
}
</style>
