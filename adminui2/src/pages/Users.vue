<script setup lang="ts">
import { computed, ref } from 'vue'
import { useToast } from 'vue-toastification'
import PaginationControls from '@/components/PaginationControls.vue'

import { usePagination } from '@/composables/usePagination'
import { useToastError } from '@/composables/useToastError'

import { Icons } from '@/util/icons'

import ConfirmModal from '@/components/ConfirmModal.vue'

import { deleteUsers, editUser, UserEditActions, type EditUsersDTO } from '@/api'

import { useUsersStore } from '@/stores/users'
import RegistrationToken from '@/components/RegistrationToken.vue'

const usersStore = useUsersStore()
usersStore.load(false)


const filterText = ref('')

const allUsers = computed(() => usersStore.users ?? [])

const filteredUsers = computed(() => {
  const arr = allUsers.value

  if (filterText.value == '') {
    return arr
  }

  const searchTerm = filterText.value.trim().toLowerCase()

  return arr.filter(
    x =>
      x.username.toLowerCase().includes(searchTerm) ||
      x.groups?.includes(searchTerm) ||
      x.mfa_type?.includes(searchTerm)
  )
})

const { next: nextPage, prev: prevPage, totalPages, currentItems: currentUsers, activePage } = usePagination(filteredUsers, 20)

const toast = useToast()
const { catcher } = useToastError()

async function updateUser(usernames: string[], action: UserEditActions) {
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
      toast.success('users ' + usernames.join(", ") + ' edited!')
    }
  } catch (e) {
    catcher(e, 'failed to edit users: ')
  }
}

async function tryDeleteUsers(rules: string[] ) {
  try {

    const resp = await deleteUsers(rules)
    usersStore.load(true)

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      toast.success('user ' + rules.join(", ") + ' deleted!')
    }
  } catch (e) {
    catcher(e, 'failed to delete user: ')
  }
}

const isCreateTokenModalOpen = ref(false)

</script>

<template>

  <main class="w-full p-4">
    <RegistrationToken v-model:isOpen="isCreateTokenModalOpen"></RegistrationToken>

    <h1 class="text-4xl font-bold">Users</h1>
      <div class="mt-6 flex flex-wrap gap-6">
        <div class="card w-full bg-base-100 shadow-xl min-w-[800px]">
          <div class="card-body">
            <div class="flex flex-row justify-between">
              <div class="tooltip" data-tip="Create Registration Token">
                <button class="btn btn-ghost btn-primary" @click="isCreateTokenModalOpen = true">Add User <font-awesome-icon
                    :icon="Icons.Add" /></button>
              </div>
              <div class="form-control">
                <label class="label">
                  <input type="text" class="input input-bordered input-sm" placeholder="Filter..."
                    v-model="filterText" />
                </label>
              </div>
            </div>

            <table class="table table-fixed w-full">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Groups</th>
                  <th>Devices</th>
                  <th>MFA Method</th>
                  <th>Locked</th>
                </tr>
              </thead>
              <tbody>
                <tr class="hover group" v-for="user in currentUsers" :key="user.username">
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ user.username }}</div>
                  </td>
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ user.groups?.join(", ") }}</div>
                  </td>
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ user.devices }}</div>
                  </td>
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ user.mfa_type }}</div>
                  </td>
                  <td class="font-mono relative">
                    <div><font-awesome-icon class="cursor-pointer" @click="updateUser([user.username], (user.locked) ? UserEditActions.Unlock : UserEditActions.Lock)" :icon="user.locked ? Icons.Locked : Icons.Unlocked" :class="user.locked ? 'text-error' : 'text-secondary'"  /></div>
                    <div v-if="user.mfa_type != 'unset'" class="mr-3 absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                      <div class="tooltip" data-tip="Reset MFA">
                        <button class="mr-3" @click="updateUser([user.username], UserEditActions.Lock)">
                          <font-awesome-icon :icon="Icons.Refresh" class="text-secondary hover:text-secondary-focus" />
                        </button>
                      </div>
                    </div>
                    <ConfirmModal @on-confirm="() => tryDeleteUsers([user.username])">
                      <button class="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                        <font-awesome-icon :icon="Icons.Delete" class="text-error hover:text-error-focus" />
                      </button>
                    </ConfirmModal>
                  </td>
                </tr>
              </tbody>
            </table>

            <div class="mt-2 w-full text-center">
              <PaginationControls @next="() => nextPage()" @prev="() => prevPage()" :current-page="activePage"
                :total-pages="totalPages" />
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
