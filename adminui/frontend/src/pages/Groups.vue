<script setup lang="ts">
import { computed, ref } from 'vue'
import { useToast } from 'vue-toastification'

import Modal from '@/components/Modal.vue'
import PaginationControls from '@/components/PaginationControls.vue'
import PageLoading from '@/components/PageLoading.vue'
import ConfirmModal from '@/components/ConfirmModal.vue'
import EmptyTable from '@/components/EmptyTable.vue'

import { useApi } from '@/composables/useApi'
import { usePagination } from '@/composables/usePagination'
import { useToastError } from '@/composables/useToastError'

import { Icons } from '@/util/icons'

import {
  getAllGroups,
  type GroupDTO,
  type GroupEditDTO,
  editGroup,
  createGroup,
  deleteGroups,
  type GroupCreateDTO,
  type MemberInfo
} from '@/api'

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

  return arr.filter(x => x.group.toLowerCase().includes(searchTerm) || x.members?.some(p => p.name.toLowerCase().includes(searchTerm)))
})

const { next: nextPage, prev: prevPage, totalPages, currentItems: currentGroups, activePage } = usePagination(filteredGroups, 20)

const isGroupModalOpen = ref(false)
const groupModalTitle = ref('')

const toast = useToast()
const { catcher } = useToastError()

// New member input and management
const newMemberInput = ref('')
const currentMembers = ref<MemberInfo[]>([])
const originalMembers = ref<MemberInfo[]>([])

type GroupType = {
  group: string
  is_edit: boolean
}

const Effects = ref<GroupType>({
  group: '',
  is_edit: false
})

// Computed properties to track changes
const addedMembers = computed(() => {
  return currentMembers.value.filter(member => !originalMembers.value.includes(member))
})

const removedMembers = computed(() => {
  return originalMembers.value.filter(member => !currentMembers.value.includes(member))
})

const hasChanges = computed(() => {
  return addedMembers.value.length > 0 || removedMembers.value.length > 0
})

function openAddGroup() {
  groupModalTitle.value = 'Add Group'

  newMemberInput.value = ''
  currentMembers.value = []
  originalMembers.value = []
  Effects.value.group = ''
  Effects.value.is_edit = false

  isGroupModalOpen.value = true
}

function openEditGroup(group: GroupDTO) {
  groupModalTitle.value = 'Edit Group'

  newMemberInput.value = ''
  currentMembers.value = [...(group.members ?? [])]
  originalMembers.value = [...(group.members ?? [])]

  Effects.value.is_edit = true

  Effects.value.group = group.group
  isGroupModalOpen.value = true
}

function addMember() {
  const name = newMemberInput.value.trim()

  if (name && !currentMembers.value.some(p => p.name.toLowerCase() == name.toLowerCase())) {
    currentMembers.value.push({
      joined: 0,
      name: name,
      sso: false
    })
    newMemberInput.value = ''
  }
}

function removeMember(member: MemberInfo) {
  const index = currentMembers.value.indexOf(member)
  if (index > -1) {
    currentMembers.value.splice(index, 1)
  }
}

function handleMemberInputKeydown(event: KeyboardEvent) {
  if (event.key === 'Enter') {
    event.preventDefault()
    addMember()
  }
}

async function createGroupUI() {
  if (Effects.value.group == '') {
    toast.error('Empty group names are not allowed')
    return
  }

  try {
    let data: GroupCreateDTO = {
      group: Effects.value.group.lastIndexOf('group:', 0) !== 0 ? 'group:' + Effects.value?.group : Effects.value?.group,
      added: []
    }

    // For new groups, send all members as additions
    data.added = currentMembers.value.map(p => p.name)

    let resp = await createGroup(data)

    refreshGroups()

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    }

    toast.success(Effects.value.group + ' updated!')
    isGroupModalOpen.value = false
  } catch (e) {
    catcher(e, 'failed to apply group change: ')
  }
}

async function updateGroup() {
  if (Effects.value.group == '') {
    toast.error('Empty group names are not allowed')
    return
  }

  try {
    let data: GroupEditDTO = {
      group: Effects.value.group.lastIndexOf('group:', 0) !== 0 ? 'group:' + Effects.value?.group : Effects.value?.group,
      added: [],
      removed: []
    }

    // For edits, send discrete changes
    if (addedMembers.value.length > 0) {
      data.added = addedMembers.value.map(p => p.name)
    }
    if (removedMembers.value.length > 0) {
      data.removed = removedMembers.value.map(p => p.name)
    }

    let resp = await editGroup(data)

    refreshGroups()

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    }

    toast.success(Effects.value.group + ' updated!')
    isGroupModalOpen.value = false
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
      <div class="mt-4">
        <div class="form-group">
          <label for="group" class="block font-medium text-gray-900 pb-2">Group Name:</label>
          <input type="text" id="group" class="input input-bordered w-full" required v-model="Effects.group" :disabled="Effects.is_edit" />
        </div>

        <div class="pt-2">
          <label class="block font-medium text-gray-900 mb-2">Members:</label>

          <!-- Add member input -->
          <div class="flex gap-2 mb-4">
            <input
              type="text"
              v-model="newMemberInput"
              @keydown="handleMemberInputKeydown"
              placeholder="Type username and press Enter..."
              class="input input-bordered flex-1"
            />
            <button
              type="button"
              @click="addMember"
              class="btn btn-primary"
              :disabled="!newMemberInput.trim() || currentMembers.some(p => p.name.includes(newMemberInput.trim()))"
            >
              Add
            </button>
          </div>

          <!-- Members badges -->
          <div class="min-h-[80px] p-3 border border-gray-300 rounded-lg bg-gray-50">
            <div v-if="currentMembers.length === 0" class="text-gray-500 text-sm">No members added yet</div>
            <div v-else class="flex flex-wrap gap-2">
              <div
                v-for="member in currentMembers"
                :key="member.name"
                class="badge badge-primary py-3"
                :class="{ 'badge-success': addedMembers.includes(member) && Effects.is_edit, 'badge-secondary': member.sso }"
              >
                <span class="font-mono pr-2 max-w-[100px] overflow-hidden text-ellipsis whitespace-nowrap"> {{ member.name }} </span>
                <button @click="removeMember(member)" class="btn btn-xs btn-circle btn-ghost hover:btn-error" type="button">
                  <font-awesome-icon :icon="Icons.Close || 'times'" class="text-xs" />
                </button>
              </div>
            </div>
          </div>

          <!-- Change summary for edits -->
          <div v-if="Effects.is_edit && hasChanges" class="mt-4 p-3 bg-info bg-opacity-10 rounded-lg">
            <h4 class="font-semibold text-sm mb-2">Changes:</h4>
            <div v-if="addedMembers.length > 0" class="text-sm text-success mb-1">
              <strong>Added: </strong
              ><span>{{
                addedMembers
                  .map(p => p.name)
                  .slice(0, 10)
                  .join(', ')
              }}</span
              ><span v-if="addedMembers.length > 10"> and {{ addedMembers.length - 10 }} more additions.</span>
            </div>
            <div v-if="removedMembers.length > 0" class="text-sm text-error">
              <strong>Removed: </strong
              ><span>{{
                removedMembers
                  .map(p => p.name)
                  .slice(0, 10)
                  .join(', ')
              }}</span
              ><span v-if="removedMembers.length > 10"> and {{ removedMembers.length - 10 }} more removals.</span>
            </div>
          </div>
        </div>

        <span class="mt-6 flex">
          <button
            class="btn btn-primary"
            @click="Effects.is_edit ? updateGroup() : createGroupUI()"
            :disabled="Effects.is_edit && !hasChanges"
          >
            Apply
          </button>

          <div class="flex flex-grow"></div>

          <button class="btn btn-secondary" @click="isGroupModalOpen = false">Cancel</button>
        </span>
      </div>
    </div>
  </Modal>

  <main class="w-full p-4">
    <PageLoading v-if="isLoading" />
    <div v-else>
      <h1 class="text-4xl font-bold mb-4">Groups</h1>
      <p>View, create and delete groups</p>
      <div class="mt-6 flex flex-wrap gap-6">
        <div class="card w-full bg-base-100 shadow-xl min-w-[800px]">
          <div class="card-body">
            <div class="flex flex-row justify-between">
              <div class="tooltip" data-tip="Add group">
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
                <tr class="hover group" v-for="group in currentGroups" :key="group.group" v-on:dblclick="openEditGroup(group)">
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ group.group }}</div>
                  </td>
                  <td class="relative">
                    <div class="flex flex-wrap gap-1">
                      <template v-if="group.members">
                        <div
                          v-for="member in group.members.slice(0, 10)"
                          :key="member.name"
                          class="badge badge-primary font-mono"
                          :class="{ 'badge-secondary': member.sso, tooltip: member.sso }"
                          :data-tip="member.sso ? 'Added via SSO' : null"
                        >
                          {{ member.name.length > 12 ? member.name.slice(0, 12) + '...' : member.name }}
                        </div>
                        <div v-if="group.members.length > 10">... {{ group.members.length - 10 }} more</div>
                      </template>
                      <div v-if="!group.members || group.members.length === 0" class="text-gray-500">No members</div>
                    </div>
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
            <EmptyTable v-if="allGroups.length == 0" text="No groups" />
            <EmptyTable v-if="allGroups.length != 0 && filteredGroups.length == 0" text="No matching groups" />

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
