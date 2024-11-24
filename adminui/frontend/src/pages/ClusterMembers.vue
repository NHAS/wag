<script setup lang="ts">
import { ref } from 'vue'
import { useToast } from 'vue-toastification'

import Modal from '@/components/Modal.vue'
import ConfirmModal from '@/components/ConfirmModal.vue'

import { addClusterMember, editClusterMember, getClusterMembers } from '@/api/cluster'

import { useApi } from '@/composables/useApi'
import { useToastError } from '@/composables/useToastError'

import { Icons } from '@/util/icons'

import { type NewNodeRequestDTO, type ClusterMember, NodeControlActions, type NodeControlRequestDTO } from '@/api'

const { data: members, silentlyRefresh: refresh } = useApi(() => getClusterMembers())

function nodeName(member: ClusterMember): string {
  let result = member.name
  if (member.name === '') {
    result = 'Connecting...'
  }

  if (member.current_node) {
    result += ' (current node)'
  }

  return result
}

const toast = useToast()
const { catcher } = useToastError()

const isMemberAddModalOpen = ref(false)
const newMemberDetails = ref<NewNodeRequestDTO>({
  connection_url: '',
  manager_url: '',
  node_name: ''
} as NewNodeRequestDTO)

const isAddLoading = ref(false)

async function addMember() {
  if (newMemberDetails.value?.connection_url.length == 0) {
    toast.error('Peer URL must be defined')
    return
  }

  try {
    isAddLoading.value = true

    const resp = await addClusterMember(newMemberDetails.value)
    refresh()

    if (resp.error_message) {
      toast.error(resp.error_message)
      return
    } else {
      toast.info(`New join token: ${resp.join_token}\nThis will not be displayed again, valid 30 seconds`, {
        timeout: false,
        closeOnClick: false,
        draggable: false
      })
    }
  } catch (e) {
    catcher(e, 'failed to add new cluster member: ', 'error_message')
  } finally {
    isAddLoading.value = false
  }
}

function openAddMemberModal() {
  isMemberAddModalOpen.value = true
  newMemberDetails.value = {
    connection_url: '',
    manager_url: '',
    node_name: ''
  } as NewNodeRequestDTO
}

async function controlNode(member: ClusterMember, action: NodeControlActions) {
  try {
    const req: NodeControlRequestDTO = {
      action: action,
      node: member.id
    }

    const resp = await editClusterMember(req)

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      toast.success(`Node ${member.id} was ${action}, successfully!`)

      refresh()
    }
  } catch (e) {
    catcher(e, 'failed to add new cluster member: ')
  }
}
</script>

<template>
  <main class="w-full p-4">
    <Modal v-model:isOpen="isMemberAddModalOpen">
      <div class="w-screen max-w-[600px]">
        <h3 class="text-lg font-bold">Add Node</h3>
        <div class="mt-2">
          <p>Add member to wag cluster</p>

          <div class="form-group">
            <label for="group" class="block font-medium text-gray-900 pt-6"
              >Peer URL:
              <input
                type="url"
                class="input input-bordered input-sm w-full"
                id="nodeURL"
                name="nodeURL"
                v-model="newMemberDetails.connection_url"
              />
            </label>
          </div>

          <div class="form-group">
            <label for="group" class="block font-medium text-gray-900 pt-6"
              >New Node Label:
              <input
                type="text"
                class="input input-bordered input-sm w-full"
                id="newNodeName"
                placeholder="(Optional)"
                v-model="newMemberDetails.node_name"
              />
            </label>
          </div>

          <div class="form-group">
            <label for="group" class="block font-medium text-gray-900 pt-6"
              >Manager URL:
              <input
                type="text"
                class="input input-bordered input-sm w-full"
                id="managerURL"
                placeholder="(Optional)"
                v-model="newMemberDetails.manager_url"
              />
            </label>
          </div>

          <span class="mt-8 flex">
            <button class="btn btn-primary" @click="() => addMember()">
              Add <span class="loading loading-spinner loading-md" v-if="isAddLoading"></span>
            </button>

            <div class="flex flex-grow"></div>

            <button class="btn btn-secondary" @click="() => (isMemberAddModalOpen = false)">Cancel</button>
          </span>
        </div>
      </div>
    </Modal>
    <h1 class="text-4xl font-bold">Cluster Members</h1>

    <button class="btn btn-ghost btn-primary" @click="openAddMemberModal">
      Add Cluster Member <font-awesome-icon :icon="Icons.Add" />
    </button>

    <div class="mt-6 flex flex-wrap gap-6">
      <div class="grid w-full grid-cols-4 gap-4">
        <div v-for="member in members" class="card-compact bg-base-100 shadow-xl min-w-96 max-w-96" :key="member.id">
          <div class="card-body">
            <h5 class="card-title overflow-hidden text-ellipsis whitespace-nowrap justify-between">
              <span>{{ nodeName(member) }}</span>
              <ConfirmModal v-if="!member.current_node" @on-confirm="() => controlNode(member, NodeControlActions.Remove)">
                <button><font-awesome-icon class="text-error hover:text-error-focus" :icon="Icons.Delete" /></button>
              </ConfirmModal>
            </h5>

            <div class="grid grid-cols-2 gap-2">
              <div>ID:</div>
              <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ member.id }}</div>

              <div>Version:</div>
              <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ member.version }}</div>

              <div>Role:</div>
              <div class="overflow-hidden text-ellipsis whitespace-nowrap">
                {{ member.leader ? 'Leader' : member.learner ? 'Learner' : member.witness ? 'Witness' : 'Member' }}
              </div>

              <div>Status:</div>
              <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ member.status }}</div>

              <div>Last Ping:</div>
              <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ member.last_ping }}</div>

              <div>{{ member.peer_urls?.length > 1 ? 'Addresses' : 'Address' }}:</div>
              <div class="grid grid-rows-subgrid grid-cols-1">
                <div class="overflow-hidden text-ellipsis whitespace-nowrap" v-for="address in member.peer_urls" :key="address">
                  {{ address }}
                </div>
              </div>
            </div>
            <div class="mt-4 flex flex-row justify-between">
              <button
                v-if="member.learner"
                class="btn btn-sm btn-info"
                @click="() => controlNode(member, NodeControlActions.Promote)"
                :disabled="member.name.length == 0"
              >
                Promote <font-awesome-icon :icon="Icons.Up" />
              </button>
              <button v-if="member.leader" class="btn btn-sm btn-info" @click="() => controlNode(member, NodeControlActions.Stepdown)">
                Step Down <font-awesome-icon :icon="Icons.Down" />
              </button>
              <span v-if="!member.witness">
                <button
                  v-if="member.drained"
                  class="btn btn-sm btn-warning"
                  @click="() => controlNode(member, NodeControlActions.Restore)"
                  :disabled="member.name.length == 0"
                >
                  Restore <font-awesome-icon :icon="Icons.Restore" />
                </button>
                <button
                  v-else
                  class="btn btn-sm btn-info"
                  @click="() => controlNode(member, NodeControlActions.Drain)"
                  :disabled="member.name.length == 0"
                >
                  Drain <font-awesome-icon :icon="Icons.Pause" />
                </button>
              </span>
            </div>
          </div>
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
