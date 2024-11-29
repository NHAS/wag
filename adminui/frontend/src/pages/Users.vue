<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useToast } from 'vue-toastification'
import { useRoute } from 'vue-router'

import PaginationControls from '@/components/PaginationControls.vue'
import ConfirmModal from '@/components/ConfirmModal.vue'
import RegistrationToken from '@/components/RegistrationToken.vue'
import EmptyTable from '@/components/EmptyTable.vue'

import { usePagination } from '@/composables/usePagination'
import { useToastError } from '@/composables/useToastError'

import { useUsersStore } from '@/stores/users'

import { Icons } from '@/util/icons'

import { deleteUsers, editUser, UserEditActions, type EditUsersDTO, type UserDTO } from '@/api'

const usersStore = useUsersStore()
usersStore.load(false)

const route = useRoute()

const filterText = ref('')

const allUsers = computed(() => usersStore.users ?? [])

const filterLocked = ref(route.params.filter == 'locked')
const filterUnsetMfa = ref(route.params.filter == 'unset')

const filteredUsers = computed(() => {
  const arr = allUsers.value
    .filter(a => a.locked || !filterLocked.value)
    .filter(a => a.mfa_type == '' || a.mfa_type == 'unset' || !filterUnsetMfa.value)

  if (filterText.value == '') {
    return arr
  }

  const searchTerm = filterText.value.trim().toLowerCase()

  return arr.filter(
    x => x.username.toLowerCase().includes(searchTerm) || x.groups?.includes(searchTerm) || x.mfa_type?.includes(searchTerm)
  )
})

const { next: nextPage, prev: prevPage, totalPages, currentItems: currentUsers, activePage } = usePagination(filteredUsers, 20)

const toast = useToast()
const { catcher } = useToastError()

async function updateUser(usernames: string[], action: UserEditActions) {
  if (usernames.length == 0) {
    return
  }

  try {
    let data: EditUsersDTO = {
      action: action,
      usernames: usernames
    }

    const resp = await editUser(data)

    usersStore.load(true)

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      toast.success('users ' + usernames.join(', ') + ' edited!')
    }
  } catch (e) {
    catcher(e, 'failed to edit users: ')
  }
}

async function tryDeleteUsers(users: string[]) {
  if (users.length == 0) {
    return
  }

  try {
    const resp = await deleteUsers(users)
    usersStore.load(true)

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      toast.success('user ' + users.join(', ') + ' deleted!')
    }
  } catch (e) {
    catcher(e, 'failed to delete user: ')
  }
}

const isCreateTokenModalOpen = ref(false)

const lastSort = ref<keyof UserDTO | null>(null)
const ascending = ref(true)

function sortUsers(by: keyof UserDTO) {
  if (lastSort.value == null || lastSort.value == by) {
    ascending.value = !ascending.value
  } else {
    ascending.value = true
    lastSort.value = by
  }

  if (usersStore.users) {
    usersStore.users.sort((a, b) => {
      const valueA = a[by]
      const valueB = b[by]
      const compair = valueA < valueB ? -1 : valueA > valueB ? 1 : 0
      return ascending.value ? compair : -compair
    })
  }
}

const selectedUsers = ref<string[]>([])
const selectAll = ref(false)

watch(selectAll, newValue => {
  if (newValue) {
    // Select all devices
    selectedUsers.value = currentUsers.value.map(d => d.username)
  } else {
    // Deselect all devices
    selectedUsers.value = []
  }
})

watch(selectedUsers, newVal => {
  if (newVal.length == 0) {
    selectAll.value = false
  }
})

const selectedUsersHasLocked = computed(() => {
  if (selectedUsers.value.length == 0) {
    return false
  }

  return allUsers.value.some(i => selectedUsers.value.includes(i.username) && i.locked)
})
</script>

<template>
  <main class="w-full p-4">
    <RegistrationToken v-model:isOpen="isCreateTokenModalOpen"></RegistrationToken>

    <h1 class="text-4xl font-bold mb-4">Users</h1>
    <p>Manage Wag VPN user accounts</p>
    <div class="mt-6 flex flex-wrap gap-6">
      <div class="card w-full bg-base-100 shadow-xl min-w-[800px]">
        <div class="card-body">
          <div class="flex flex-row justify-between">
            <span class="flex">
              <div class="tooltip" data-tip="Create Registration Token">
                <button class="btn btn-ghost btn-primary" @click="isCreateTokenModalOpen = true">
                  Add User <font-awesome-icon :icon="Icons.Add" />
                </button>
              </div>
              <div class="tooltip" :data-tip="(selectedUsersHasLocked ? 'Unlock ' : 'Lock ') + selectedUsers.length + ' users'">
                <button
                  @click="updateUser(selectedUsers, selectedUsersHasLocked ? UserEditActions.Unlock : UserEditActions.Lock)"
                  class="btn btn-ghost btn-primary"
                >
                  {{ selectedUsersHasLocked ? 'Unlock' : 'Lock' }}
                  <font-awesome-icon :icon="selectedUsersHasLocked ? Icons.Unlocked : Icons.Locked" />
                </button>
              </div>
              <div class="tooltip" :data-tip="'Reset ' + selectedUsers.length + ' users MFA'">
                <button @click="updateUser(selectedUsers, UserEditActions.ResetMFA)" class="btn btn-ghost btn-primary">
                  Reset MFA <font-awesome-icon :icon="Icons.Refresh" />
                </button>
              </div>
              <div class="tooltip" :data-tip="'Delete ' + selectedUsers.length + ' users'">
                <ConfirmModal @on-confirm="() => deleteUsers(selectedUsers)">
                  <button class="btn btn-ghost btn-primary">Bulk Delete<font-awesome-icon :icon="Icons.Delete" /></button>
                </ConfirmModal>
              </div>
            </span>

            <span class="flex">
              <label class="label cursor-pointer mr-4">
                <span class="label-text mr-2">Unset MFA</span>
                <input v-model="filterUnsetMfa" type="checkbox" class="toggle toggle-primary" />
              </label>
              <label class="label cursor-pointer mr-4">
                <span class="label-text mr-2">Locked</span>
                <input v-model="filterLocked" type="checkbox" class="toggle toggle-primary" />
              </label>
              <label class="label">
                <input type="text" class="input input-bordered input-sm" placeholder="Filter..." v-model="filterText" />
              </label>
            </span>
          </div>

          <table class="table table-fixed w-full">
            <thead>
              <tr>
                <th class="w-10">
                  <input type="checkbox" class="checkbox" v-model="selectAll" />
                </th>
                <th class="cursor-pointer" @click="sortUsers('username')">Username</th>
                <th class="cursor-pointer" @click="sortUsers('groups')">Groups</th>
                <th class="cursor-pointer" @click="sortUsers('devices')">Devices</th>
                <th class="cursor-pointer" @click="sortUsers('mfa_type')">MFA Method</th>
                <th class="cursor-pointer" @click="sortUsers('locked')">Locked</th>
              </tr>
            </thead>
            <tbody>
              <tr class="hover group" v-for="user in currentUsers" :key="user.username">
                <th>
                  <input type="checkbox" class="checkbox" v-model="selectedUsers" :value="user.username" />
                </th>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ user.username }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ user.groups?.join(', ') }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ user.devices }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ user.mfa_type }}</div>
                </td>
                <td class="font-mono relative">
                  <div>
                    <font-awesome-icon
                      class="cursor-pointer"
                      @click="updateUser([user.username], user.locked ? UserEditActions.Unlock : UserEditActions.Lock)"
                      :icon="user.locked ? Icons.Locked : Icons.Unlocked"
                      :class="user.locked ? 'text-error' : 'text-secondary'"
                    />
                  </div>
                  <div
                    v-if="user.mfa_type != 'unset'"
                    class="mr-3 absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity duration-200"
                  >
                    <div class="tooltip" data-tip="Reset MFA">
                      <button class="mr-3" @click="updateUser([user.username], UserEditActions.Lock)">
                        <font-awesome-icon :icon="Icons.Refresh" class="text-secondary hover:text-secondary-focus" />
                      </button>
                    </div>
                  </div>
                  <ConfirmModal @on-confirm="() => tryDeleteUsers([user.username])">
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
          <EmptyTable v-if="allUsers.length == 0" text="No users" />
          <EmptyTable v-if="allUsers.length != 0 && currentUsers.length == 0" text="No matching users" />

          <div class="mt-2 w-full text-center">
            <PaginationControls @next="() => nextPage()" @prev="() => prevPage()" :current-page="activePage" :total-pages="totalPages" />
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
