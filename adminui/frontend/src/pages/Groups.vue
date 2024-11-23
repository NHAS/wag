<script setup lang="ts">
import { computed, ref } from 'vue'
import { useToast } from 'vue-toastification'

import Modal from '@/components/Modal.vue'
import PaginationControls from '@/components/PaginationControls.vue'
import PageLoading from '@/components/PageLoading.vue'
import ConfirmModal from '@/components/ConfirmModal.vue'

import { useApi } from '@/composables/useApi'
import { usePagination } from '@/composables/usePagination'
import { useToastError } from '@/composables/useToastError'
import { useTextareaInput } from '@/composables/useTextareaInput'

import { Icons } from '@/util/icons'

import { getAllGroups, type GroupDTO, editGroup, createGroup, deleteGroups } from '@/api'

const { data: groupsData, isLoading: isLoadingRules, silentlyRefresh: refreshGroups } = useApi(() => getAllGroups())

const isLoading = computed(() => {
  return isLoadingRules.value
})

const filterText = ref('')

const allGroups = computed(() => groupsData.value ?? [])

const filteredGroups = computed(() => {
  const arr = allGroups.value

  if (filterText.value == '') {
    return arr
  }

  const searchTerm = filterText.value.trim().toLowerCase()

  return arr.filter(x => x.group.toLowerCase().includes(searchTerm) || x.members?.includes(searchTerm))
})

const { next: nextPage, prev: prevPage, totalPages, currentItems: currentGroups, activePage } = usePagination(filteredGroups, 20)

const isGroupModalOpen = ref(false)
const groupModalTitle = ref('')

const toast = useToast()
const { catcher } = useToastError()

const { Input: GroupMembers, Arr: GroupMembersArr } = useTextareaInput()

type GroupType = {
  is_edit: boolean
  group: string
}

const Effects = ref<GroupType>({
  is_edit: false,
  group: ''
})

function openAddGroup() {
  groupModalTitle.value = 'Add Rule'

  GroupMembers.value = ''
  Effects.value.group = ''
  Effects.value.is_edit = false

  isGroupModalOpen.value = true
}

function openEditGroup(group: GroupDTO) {
  groupModalTitle.value = 'Edit Rule'

  GroupMembers.value = group.members?.join('\n') ?? ''

  Effects.value.group = group.group
  Effects.value.is_edit = true

  isGroupModalOpen.value = true
}

async function updateGroup() {
  if (Effects.value.group == '') {
    toast.error('Empty group names are not allowed')
    return
  }

  try {
    let data: GroupDTO = {
      group: Effects.value.group.lastIndexOf('group:', 0) !== 0 ? 'group:' + Effects.value?.group : Effects.value?.group,
      members: GroupMembersArr.value ?? []
    }

    let resp = null
    if (Effects.value.is_edit) {
      resp = await editGroup(data)
    } else {
      resp = await createGroup(data)
    }

    refreshGroups()

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      toast.success(Effects.value.group + ' edited!')
      isGroupModalOpen.value = false
    }
  } catch (e) {
    catcher(e, 'failed to apply group change: ')
  }
}

async function tryDeleteGroups(groups: string[]) {
  try {
    const resp = await deleteGroups(groups)

    refreshGroups()

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      toast.success(groups.join(',') + ' deleted!')
    }
  } catch (e) {
    catcher(e, 'failed delete groups: ')
  }
}
</script>

<template>
  <Modal v-model:isOpen="isGroupModalOpen">
    <div class="w-screen max-w-[600px]">
      <h3 class="text-lg font-bold">{{ groupModalTitle }}</h3>
      <div class="mt-8">
        <p>Make changes to your group.</p>

        <div class="form-group">
          <label for="group" class="block font-medium text-gray-900 pt-6">Group:</label>
          <input
            type="text"
            id="group"
            class="input input-bordered input-sm w-full"
            required
            v-model="Effects.group"
            :disabled="Effects.is_edit"
          />
        </div>

        <label for="members" class="block font-medium text-gray-900 pt-6">Members:</label>
        <textarea class="rules-input textarea textarea-bordered w-full font-mono" rows="3" v-model="GroupMembers"></textarea>

        <span class="mt-4 flex">
          <button class="btn btn-primary" @click="() => updateGroup()">Apply</button>

          <div class="flex flex-grow"></div>

          <button class="btn btn-secondary" @click="() => (isGroupModalOpen = false)">Cancel</button>
        </span>
      </div>
    </div>
  </Modal>

  <main class="w-full p-4">
    <PageLoading v-if="isLoading" />
    <div v-else>
      <h1 class="text-4xl font-bold mb-4">Rules</h1>
      <p>View, create and delete groups.</p>
      <div class="mt-6 flex flex-wrap gap-6">
        <div class="card w-full bg-base-100 shadow-xl min-w-[800px]">
          <div class="card-body">
            <div class="flex flex-row justify-between">
              <div class="tooltip" data-tip="Add rule">
                <button class="btn btn-ghost btn-primary" @click="openAddGroup">Add Group <font-awesome-icon :icon="Icons.Add" /></button>
              </div>
              <div class="form-control">
                <label class="label">
                  <input type="text" class="input input-bordered input-sm" placeholder="Filter..." v-model="filterText" />
                </label>
              </div>
            </div>

            <table class="table table-fixed w-full">
              <thead>
                <tr>
                  <th>Group</th>
                  <th>Members</th>
                </tr>
              </thead>
              <tbody>
                <tr class="hover group" v-for="group in currentGroups" :key="group.group">
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ group.group }}</div>
                  </td>
                  <td class="font-mono relative">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ group.members?.join(', ') || '-' }}</div>
                    <div
                      class="mr-3 absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity duration-200"
                    >
                      <button class="mr-3" @click="openEditGroup(group)">
                        <font-awesome-icon :icon="Icons.Edit" class="text-secondary hover:text-secondary-focus" />
                      </button>
                    </div>
                    <ConfirmModal @on-confirm="() => tryDeleteGroups([group.group])">
                      <button
                        class="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity duration-200"
                      >
                        <font-awesome-icon :icon="Icons.Delete" class="text-error hover:text-error-focus" />
                      </button>
                    </ConfirmModal>
                  </td>
                </tr>
              </tbody>
            </table>

            <div class="mt-2 w-full text-center">
              <PaginationControls @next="() => nextPage()" @prev="() => prevPage()" :current-page="activePage" :total-pages="totalPages" />
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>
</template>

<style scoped>
.hashlist-table.table-sm :where(th, td) {
  padding-top: 0.4rem;
  padding-bottom: 0.4rem;
}
</style>
