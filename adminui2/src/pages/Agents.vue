<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useToast } from 'vue-toastification'

import EmptyTable from '@/components/EmptyTable.vue'

import { adminAgentSetMaintenance } from '@/api/admin'
import type { AgentDTO } from '@/api/types'

import { useToastError } from '@/composables/useToastError'

import { useAuthStore } from '@/stores/auth'
import { useAgentsStore } from '@/stores/rules'

import { Icons } from '@/util/icons'
import { formatDeviceName } from '@/util/formatDeviceName'

const AgentStatusHealthy = 'AgentStatusHealthy'
const AgentStatusUnhealthyButConnected = 'AgentStatusUnhealthyButConnected'
const AgentStatusUnhealthyAndDisconnected = 'AgentStatusUnhealthyAndDisconnected'
// const AgentStatusDead = 'AgentStatusDead'

const agentsStore = useAgentsStore()
const { agents: allAgents } = storeToRefs(agentsStore)
agentsStore.load(true)

const authStore = useAuthStore()
const { isAdmin } = storeToRefs(authStore)

const toast = useToast()
const { catcher } = useToastError()

async function toggleMaintenance(agent: AgentDTO) {
  try {
    const is_maintenance_mode = !agent.is_maintenance_mode
    await adminAgentSetMaintenance(agent.id, {
      is_maintenance_mode
    })
    toast.info(`Set agent ${agent.name} maintenance to ${is_maintenance_mode}`)
  } catch (e: any) {
    catcher(e)
  } finally {
    agentsStore.load(true)
  }
}
</script>

<template>
  <main class="w-full p-4">
    <h1 class="text-4xl font-bold">Agents</h1>
    <div class="mt-6 flex flex-wrap gap-6">
      <div class="grow">
        <div class="stats shadow">
          <div class="stat">
            <div class="stat-title">Agents Online & Healthy</div>
            <div class="stat-value flex justify-between">
              <span
                >{{ allAgents.filter(x => x.agent_info.status == AgentStatusHealthy).length ?? '?' }}/{{ allAgents.length ?? '?' }}</span
              >
              <span class="mt-1 text-2xl text-primary">
                <font-awesome-icon :icon="Icons.Agent" />
              </span>
            </div>
          </div>
        </div>
      </div>

      <div class="flex basis-full"></div>

      <div class="card bg-base-100 shadow-xl">
        <div class="card-body">
          <h2 class="card-title">Agent List</h2>
          <table class="table w-full">
            <thead>
              <tr>
                <th>Name</th>
                <th v-if="isAdmin">Version</th>
                <th>Devices</th>
                <th>Status</th>
                <th v-if="isAdmin || allAgents.some(agent => agent.is_maintenance_mode)">Maintenance</th>
              </tr>
            </thead>
            <tbody class="first-col-bold">
              <tr class="hover" v-for="agent in allAgents" :key="agent.id">
                <td>{{ agent.name }}</td>
                <td v-if="isAdmin" class="font-mono">{{ agent.agent_info.version }}</td>
                <td>
                  <span v-for="device in agent.agent_devices" :key="device.device_id + device.device_name">
                    <font-awesome-icon :icon="Icons.GPU" v-if="device.device_type == 'GPU'" />
                    <font-awesome-icon :icon="Icons.CPU" v-else />
                    {{ formatDeviceName(device.device_name) }} ({{ device.temp }} °c)
                    <br />
                  </span>
                </td>

                <td class="text-center">
                  <div
                    class="badge badge-warning badge-sm m-auto block"
                    title="Marked for maintenance"
                    v-if="agent.is_maintenance_mode"
                  ></div>
                  <div
                    class="badge badge-accent badge-sm m-auto block"
                    v-else-if="agent.agent_info.status == AgentStatusHealthy"
                    title="Healthy"
                  ></div>
                  <div
                    class="badge badge-warning badge-sm m-auto block"
                    title="Unhealthy"
                    v-else-if="
                      agent.agent_info.status == AgentStatusUnhealthyAndDisconnected ||
                      agent.agent_info.status == AgentStatusUnhealthyButConnected
                    "
                  ></div>
                  <div class="badge badge-ghost badge-sm m-auto block" title="Dead" v-else></div>
                </td>

                <td v-if="isAdmin">
                  <input
                    type="checkbox"
                    class="toggle toggle-sm m-auto block"
                    v-model="agent.is_maintenance_mode"
                    @click="toggleMaintenance(agent)"
                  />
                </td>
                <td v-else-if="agent.is_maintenance_mode">
                  <font-awesome-icon :icon="Icons.Maintenance" /><span class="ml-2">In maintenance</span>
                </td>
              </tr>
            </tbody>
          </table>
          <EmptyTable v-if="allAgents.length == 0" text="No Agents Yet" icon="fa-robot" />
        </div>
      </div>
    </div>
  </main>
</template>

<style scoped>
thead > tr > th {
  background: none !important;
  border-bottom-width: 1px;
  /* border-bottom: 1px solid black; */
}

.first-col-bold > tr td:first-of-type {
  font-weight: bold;
}
</style>
