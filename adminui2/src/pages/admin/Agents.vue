<script setup lang="ts">
import { useToast } from 'vue-toastification'
import { ref, computed } from 'vue'

import ConfirmModal from '@/components/ConfirmModal.vue'
import Modal from '@/components/Modal.vue'
import IconButton from '@/components/IconButton.vue'
import InfoTip from '@/components/InfoTip.vue'

import {
  adminAgentSetMaintenance,
  adminCreateAgentRegistrationKey,
  adminDeleteAgent,
  adminDeleteAgentRegistrationKey,
  adminGetAgentRegistrationKeys
} from '@/api/admin'
import { getAllAgents } from '@/api/rules'

import { useApi } from '@/composables/useApi'
import { useToastError } from '@/composables/useToastError'

import { Icons } from '@/util/icons'
import { formatDeviceName } from '@/util/formatDeviceName'

import type { AgentDTO } from '@/api'

const AgentStatusHealthy = 'AgentStatusHealthy'
const AgentStatusUnhealthyButConnected = 'AgentStatusUnhealthyButConnected'
const AgentStatusUnhealthyAndDisconnected = 'AgentStatusUnhealthyAndDisconnected'

const isRegistrationModalOpen = ref(false)

const { data: agents, silentlyRefresh: fetchAgents, isLoading } = useApi(getAllAgents)

const { data: registrationKeys, silentlyRefresh: fetchRegistrationKeys } = useApi(adminGetAgentRegistrationKeys)

const toast = useToast()
const { catcher } = useToastError()

const newRegKeyEphemeral = ref(false)
const newRegKeyName = ref('')
const newRegKeyValidationError = computed(() => {
  if (newRegKeyName.value.length > 30) {
    return 'Name too long'
  }

  return null
})

const isDisplayKeyModalOpen = ref(false)
const keyToDisplay = ref('')
const disableTlsVerification = ref(false)

const isLoadingRegister = ref(false)

const commandToRun = computed(() => {
  const baseUrl = window.location.origin
  const key = keyToDisplay.value

  return `curl ${baseUrl}/agent-assets/install.sh ${disableTlsVerification.value ? '-k ' : ''}| PHATCRACK_HOST=${baseUrl} PHATCRACK_REGISTRATION_KEY=${key}${disableTlsVerification.value ? ' DISABLE_TLS_VERIFICATON=1' : ''} bash`
})

async function onCreateNewRegistrationKey() {
  isLoadingRegister.value = true
  try {
    const res = await adminCreateAgentRegistrationKey({
      name: newRegKeyName.value,
      for_ephemeral_agent: newRegKeyEphemeral.value
    })

    toast.info('Created new registration key')

    keyToDisplay.value = res.key
    isDisplayKeyModalOpen.value = true
    isRegistrationModalOpen.value = false
  } catch (e: any) {
    catcher(e)
  } finally {
    isLoadingRegister.value = false
    fetchRegistrationKeys()
  }
}

async function onDeleteAgent(id: string) {
  try {
    await adminDeleteAgent(id)
    toast.info('Deleted agent')
  } catch (e: any) {
    catcher(e)
  } finally {
    fetchAgents()
  }
}

async function onDeleteRegKey(id: string) {
  try {
    await adminDeleteAgentRegistrationKey(id)
    toast.info('Deleted agent registration key')
  } catch (e: any) {
    catcher(e)
  } finally {
    fetchRegistrationKeys()
  }
}

async function copyCommand() {
  await navigator.clipboard.writeText(commandToRun.value)
  toast.success('Copied to clipboard')
}

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
    fetchAgents()
  }
}
</script>

<template>
  <Modal v-model:isOpen="isDisplayKeyModalOpen">
    <div>
      <div>
        <h3 class="text-lg font-bold">Agent enrolment script</h3>

        <p>
          Run the following script on the server you want to use for hash cracking. This script will install the agent and register it with
          the server.
        </p>

        <div class="bg-slate-200 border-slate-200 mt-4 p-4 rounded-lg">
          <pre class="whitespace-pre-line overflow-wrap break-words max-w-[60vw]">
            {{ commandToRun }}
          </pre>

          <div class="flex justify-end">
            <div class="tooltip" data-tip="Copy">
              <button class="btn btn-xs btn-outline btn-ghost" @click="copyCommand">
                <font-awesome-icon :icon="Icons.Clipboard" />
              </button>
            </div>
          </div>
        </div>

        <div class="form-control">
          <label class="label font-bold"
            ><span class="label-text"
              >Disable TLS Verification?
              <InfoTip
                tooltip="If this is checked, the agent will not verify the server's TLS certificate. This is not recommended, but can be useful if you are using a self-signed certificate."
              /> </span></label
          ><input v-model="disableTlsVerification" type="checkbox" class="checkbox" />
        </div>
      </div>
    </div>
  </Modal>

  <Modal v-model:isOpen="isRegistrationModalOpen">
    <div class="flex">
      <div>
        <h3 class="text-lg font-bold mr-8">Create a new registration key</h3>
        <div class="form-control">
          <label class="label font-bold">
            <span class="label-text">Name (optional)</span>
          </label>
          <input v-model="newRegKeyName" type="text" placeholder="crack01" class="input input-bordered w-full max-w-xs" />
        </div>
        <div class="form-control">
          <label class="label font-bold"
            ><span class="label-text"
              >Is agent ephemeral?
              <span class="tooltip font-normal" data-tip="Ephemeral agents are removed after 2 minutes of inactivity">
                <font-awesome-icon :icon="Icons.Info" />
              </span> </span
          ></label>
          <input v-model="newRegKeyEphemeral" type="checkbox" class="checkbox" />
        </div>
        <div class="form-control mt-3">
          <span class="tooltip" :data-tip="newRegKeyValidationError">
            <button
              @click="onCreateNewRegistrationKey"
              :disabled="newRegKeyValidationError != null || isLoadingRegister"
              class="btn btn-primary w-full"
            >
              <span class="loading loading-spinner loading-md" v-if="isLoadingRegister"></span>
              Create
            </button>
          </span>
        </div>
      </div>
    </div>
  </Modal>

  <main class="w-full p-4">
    <h1 class="text-4xl font-bold">Agent Management</h1>

    <div class="mt-6 flex flex-wrap gap-6">
      <div class="card bg-base-100 shadow-xl">
        <div class="card-body">
          <div class="flex flex-row justify-between">
            <h2 class="card-title mr-2">Agents</h2>
            <div>
              <button class="btn btn-primary btn-sm ml-2" @click="() => (isRegistrationModalOpen = true)">
                <font-awesome-icon :icon="Icons.Add" />
                Register Agent
              </button>
            </div>
          </div>

          <div v-if="isLoading" class="flex h-56 h-full w-56 w-full justify-center self-center">
            <span class="loading loading-spinner loading-lg"></span>
          </div>
          <table v-else class="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Version</th>
                <th>Devices</th>
                <th>Status</th>
                <th>Maintenance</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr class="hover" v-for="agent in agents?.agents" :key="agent.id">
                <td>
                  <strong>{{ agent.name }}</strong>
                </td>
                <td class="font-mono">{{ agent.agent_info.version }}</td>
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

                <td>
                  <input
                    type="checkbox"
                    class="toggle toggle-sm m-auto block"
                    v-model="agent.is_maintenance_mode"
                    @click="toggleMaintenance(agent)"
                  />
                </td>

                <td class="text-center">
                  <ConfirmModal @on-confirm="() => onDeleteAgent(agent.id)">
                    <IconButton :icon="Icons.Delete" color="error" tooltip="Delete" />
                  </ConfirmModal>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="mt-6 flex flex-wrap gap-6" v-if="(registrationKeys?.agent_registration_keys ?? []).length > 0">
      <div class="card bg-base-100 shadow-xl">
        <div class="card-body">
          <div class="flex flex-row justify-between">
            <h2 class="card-title mr-2">Existing Registration Keys</h2>
          </div>

          <table class="table table-sm">
            <thead>
              <tr>
                <th>Name</th>
                <th>
                  Key
                  <span class="tooltip font-normal" data-tip="The full key cannot be shown again">
                    <font-awesome-icon :icon="Icons.Info" class="ml-1" />
                  </span>
                </th>
                <th>Ephemeral Agent?</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="key in registrationKeys?.agent_registration_keys ?? []" :key="key.id">
                <td>
                  <strong>{{ key.name || '-' }}</strong>
                </td>
                <td class="font-mono">{{ key.key_hint }}</td>
                <td>
                  <font-awesome-icon :icon="Icons.Tick" v-if="key.for_ephemeral_agent" />
                </td>
                <td>
                  <ConfirmModal @on-confirm="() => onDeleteRegKey(key.id)">
                    <IconButton :icon="Icons.Delete" color="error" tooltip="Delete" />
                  </ConfirmModal>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </main>
</template>
