<script setup lang="ts">
import { useToast } from 'vue-toastification'
import { ref, computed, watch, reactive } from 'vue'
import { storeToRefs } from 'pinia'

import Modal from '@/components/Modal.vue'
import ConfirmModal from '@/components/ConfirmModal.vue'
import IconButton from '@/components/IconButton.vue'
import PaginationControls from '@/components/PaginationControls.vue'
import CheckboxSet from '@/components/CheckboxSet.vue'

import {
  adminCreateServiceAccount,
  adminCreateUser,
  adminDeleteUser,
  adminGetAllUsers,
  adminUpdateUser,
  adminUpdateUserPassword
} from '@/api/admin'
import { userAssignableRoles, UserRole, userSignupRoles } from '@/api/users'

import { useApi } from '@/composables/useApi'
import { usePagination } from '@/composables/usePagination'
import { useToastError } from '@/composables/useToastError'

import { useAuthStore } from '@/stores/auth'

import { Icons } from '@/util/icons'

const isUserCreateOpen = ref(false)
const isServiceAccountCreateOpen = ref(false)
const isUserEditOpen = ref(false)
const isUserManagePasswordOpen = ref(false)
const userIdToManagePassword = ref('')

const { data: _allUsers, fetchData: fetchUsers, silentlyRefresh: silentlyFetchUsers, isLoading } = useApi(adminGetAllUsers)

const allUsers = computed(() => {
  return {
    users: [...(_allUsers.value?.users ?? [])].sort((a, b) => a.username.localeCompare(b.username))
  }
})

const userToManagePassword = computed(() => allUsers.value?.users.find(x => x.id === userIdToManagePassword.value))

const editInputs = reactive({
  id: '',
  username: '',
  passwordLocked: false,
  roleMap: {} as { [key: string]: boolean }
})

watch(
  () => editInputs.roleMap,
  (current, last) => {
    // These two are mutually exclusive
    if (current[UserRole.Standard] && current[UserRole.Admin]) {
      if (last[UserRole.Standard]) {
        editInputs.roleMap = {
          ...current,
          [UserRole.Standard]: false
        }
      }

      if (last[UserRole.Admin]) {
        editInputs.roleMap = {
          ...current,
          [UserRole.Admin]: false
        }
      }
    }
  }
)

function onOpenEditUser(userId: string) {
  const userToEdit = allUsers.value?.users?.find(x => x.id === userId) ?? null
  if (!userToEdit) {
    return
  }

  editInputs.id = userId
  editInputs.username = userToEdit.username

  const roleEntries = userAssignableRoles.map(x => [x, userToEdit.roles.includes(x)])
  editInputs.roleMap = Object.fromEntries(roleEntries)

  isUserEditOpen.value = true
}

function onOpenManagePassword(userId: string) {
  userIdToManagePassword.value = userId
  isUserManagePasswordOpen.value = true
}

async function onSaveUser() {
  const roles = Object.entries(editInputs.roleMap)
    .filter(([, val]) => val === true)
    .map(([key]) => key)

  try {
    await adminUpdateUser(editInputs.id, {
      username: editInputs.username,
      roles
    })
    toast.success('Saved user')
  } catch (e) {
    catcher(e, 'Failed to save user: ')
  } finally {
    silentlyFetchUsers()
  }
}

const filterText = ref('')

const usersToPaginate = computed(() => {
  const arr = allUsers.value?.users ?? []

  if (filterText.value == '') {
    return arr
  }

  return arr.filter(x => x.username.toLowerCase().includes(filterText.value.trim()))
})

const {
  next: nextPage,
  prev: prevPage,
  totalPages: totalPages,
  currentItems: paginatedUsers,
  activePage
} = usePagination(usersToPaginate, 10)

const possibleRoles = [...userSignupRoles]

const newUserUsername = ref('')
const newUserLockPassword = ref(false)
const newUserGenPassword = ref(false)
const newUserPassword = ref('')
const newUserRole = ref(UserRole.Standard)

watch(newUserLockPassword, newVal => {
  if (newVal === true) {
    newUserPassword.value = ''
    newUserGenPassword.value = false
  }
})

watch(newUserGenPassword, newVal => {
  if (newVal === true) {
    newUserPassword.value = ''
  }
})

const serviceAccountValidationError = computed(() => {
  if (newUserUsername.value.length < 3) {
    return 'Username too short'
  }
  return null
})

const newUserValidationError = computed(() => {
  if (newUserUsername.value.length < 3) {
    return 'Username too short'
  }

  if (!newUserLockPassword.value && !newUserGenPassword.value && newUserPassword.value.length < 16) {
    return 'Password too short'
  }

  return null
})

const toast = useToast()
const { catcher } = useToastError()

async function onCreateUser() {
  try {
    const genPassword = newUserGenPassword.value

    const res = await adminCreateUser({
      username: newUserUsername.value,
      gen_password: genPassword,
      lock_password: newUserLockPassword.value,
      password: newUserPassword.value,
      roles: [newUserRole.value]
    })

    if (genPassword) {
      toast.info(
        `Created new user ${res.username}.\n\nGenerated Password (note this down, won't be displayed again):\n${res.generated_password}`,
        {
          // force user to dismiss this
          timeout: false,
          closeOnClick: false,
          draggable: false
        }
      )
    } else {
      toast.success('Created new user: ' + res.username)
    }
  } catch (e: any) {
    catcher(e)
  } finally {
    fetchUsers()
  }
}

async function onCreateServiceAccount() {
  try {
    const res = await adminCreateServiceAccount({
      username: newUserUsername.value,
      roles: [newUserRole.value]
    })

    toast.info(`Created new service account ${res.username}.\n\n API Key (note this down, won't be displayed again):\n${res.api_key}`, {
      // force user to dismiss this
      timeout: false,
      closeOnClick: false,
      draggable: false
    })
  } catch (e: any) {
    catcher(e)
  } finally {
    fetchUsers()
  }
}

const authStore = useAuthStore()
const { loggedInUser } = storeToRefs(authStore)

async function onDeleteUser(id: string) {
  if (loggedInUser.value?.id === id) {
    toast.error("You can't delete your own user")
    return
  }

  try {
    await adminDeleteUser(id)
    toast.info('Deleted user')
  } catch (e: any) {
    catcher(e)
  } finally {
    fetchUsers()
  }
}

async function onRemovePassword(id: string) {
  try {
    await adminUpdateUserPassword(id, 'remove')
    const username = userToManagePassword.value?.username ?? 'Unknown User'
    toast.info('Removed password from ' + username)
  } catch (e) {
    catcher(e)
  } finally {
    fetchUsers()
  }
}

async function onGenerateNewPassword(id: string) {
  try {
    const res = await adminUpdateUserPassword(id, 'generate')
    const username = userToManagePassword.value?.username ?? 'Unknown User'
    toast.info(`Generated new password for ${username} (note this down, won't be displayed again):\n${res.generated_password}`, {
      // force user to dismiss this
      timeout: false,
      closeOnClick: false,
      draggable: false
    })
  } catch (e) {
    catcher(e)
  } finally {
    fetchUsers()
  }
}
</script>

<template>
  <div class="flex flex-row justify-between">
    <Modal v-model:is-open="isUserManagePasswordOpen">
      <h3 class="text-lg font-bold mr-12 mb-4">Manage {{ userToManagePassword?.username }}'s Password</h3>

      <p v-if="userToManagePassword?.is_password_locked">User does not have a password set.</p>
      <p v-else>User currently has a password set.</p>

      <div class="form-control mt-2">
        <label class="label font-bold"><span class="label-text">Actions</span></label>
      </div>
      <button
        class="btn w-full btn-sm mb-2"
        @click="() => onRemovePassword(userIdToManagePassword)"
        v-if="!userToManagePassword?.is_password_locked"
      >
        Remove Password
      </button>
      <button class="btn w-full btn-sm" @click="() => onGenerateNewPassword(userIdToManagePassword)">Generate new password</button>
    </Modal>

    <Modal v-model:is-open="isUserEditOpen">
      <h3 class="text-lg font-bold">Edit User</h3>

      <div class="form-control">
        <label for="" class="label font-bold"><span class="label-text">Username</span> </label>
        <input v-model="editInputs.username" type="text" placeholder="j.smith" class="input input-bordered w-full max-w-xs" />
      </div>

      <div class="form-control mt-3">
        <label class="label font-bold">
          <span class="label-text">Roles</span>
        </label>
        <CheckboxSet v-model="editInputs.roleMap" />
      </div>

      <div class="form-control mt-6">
        <span class="tooltip">
          <button @click="onSaveUser" class="btn btn-primary w-full">Save</button>
        </span>
      </div>
    </Modal>

    <Modal v-model:isOpen="isUserCreateOpen">
      <h3 class="text-lg font-bold">Create a new user</h3>

      <div class="form-control">
        <label class="label font-bold">
          <span class="label-text">Username</span>
        </label>
        <input v-model="newUserUsername" type="text" placeholder="j.smith" class="input input-bordered w-full max-w-xs" />
      </div>

      <div class="form-control">
        <label class="label font-bold"><span class="label-text">SSO-only User?</span></label>
        <input type="checkbox" v-model="newUserLockPassword" class="checkbox" />
      </div>

      <div class="form-control">
        <label class="label font-bold">
          <span class="label-text">Password</span>
          <span @click="() => (newUserGenPassword = !newUserGenPassword)" class="tooltip cursor-pointer" v-if="!newUserLockPassword">
            <font-awesome-icon :icon="Icons.RandomlyGenerated" />
          </span>
        </label>
        <input
          v-model="newUserPassword"
          type="password"
          :placeholder="newUserLockPassword ? '(Locked)' : newUserGenPassword ? 'Randomly generated' : 'hunter2'"
          class="input input-bordered w-full max-w-xs"
          :disabled="newUserGenPassword || newUserLockPassword"
        />
      </div>

      <div class="form-control">
        <label class="label font-bold">
          <span class="label-text">Role</span>
        </label>
        <select class="select select-bordered" v-model="newUserRole">
          <option v-for="role in possibleRoles" :value="role" :key="role">
            {{ role }}
          </option>
        </select>
      </div>

      <div class="form-control mt-3">
        <span class="tooltip" :data-tip="newUserValidationError">
          <button @click="onCreateUser" :disabled="newUserValidationError != null" class="btn btn-primary w-full">Create</button>
        </span>
      </div>
    </Modal>
    <Modal v-model:isOpen="isServiceAccountCreateOpen">
      <h3 class="text-lg font-bold">Create a new service account</h3>

      <div class="form-control">
        <label class="label font-bold">
          <span class="label-text">Service Account Name</span>
        </label>
        <input v-model="newUserUsername" type="text" placeholder="mr.roboto" class="input input-bordered w-full max-w-xs" />
      </div>

      <div class="form-control">
        <label class="label font-bold">
          <span class="label-text">Role</span>
        </label>
        <select class="select select-bordered" v-model="newUserRole">
          <option v-for="role in possibleRoles" :value="role" :key="role">
            {{ role }}
          </option>
        </select>
      </div>

      <div class="form-control mt-3">
        <span class="tooltip" :data-tip="serviceAccountValidationError">
          <button @click="onCreateServiceAccount" :disabled="serviceAccountValidationError != null" class="btn btn-primary w-full">
            Create
          </button>
        </span>
      </div>
    </Modal>
    <h2 class="card-title">Users</h2>
    <div>
      <div class="form-control inline-block">
        <label class="label">
          <span class="label-text mr-2">Filter</span>
          <input type="text" class="input input-bordered input-sm" placeholder="Username" v-model="filterText" />
        </label>
      </div>
      <button class="btn btn-primary btn-sm" @click="() => (isUserCreateOpen = true)">Create User</button>
      <button class="btn btn-primary btn-sm ml-1" @click="() => (isServiceAccountCreateOpen = true)">Create Service Account</button>
    </div>
  </div>

  <div v-if="isLoading" class="flex h-56 h-full w-56 w-full justify-center self-center">
    <span class="loading loading-spinner loading-lg"></span>
  </div>
  <table v-else class="table w-full">
    <thead>
      <tr>
        <th>Username</th>
        <th>Roles</th>
        <th>Has Password Set?</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      <tr class="hover" v-for="user in paginatedUsers" :key="user.id">
        <td>
          <strong>{{ user.username }}</strong>
        </td>
        <td>
          {{ user.roles.join(', ') }}
        </td>
        <td>
          <font-awesome-icon :icon="Icons.Tick" v-if="!user.is_password_locked" />
        </td>
        <td>
          <ConfirmModal @on-confirm="() => onDeleteUser(user.id)">
            <IconButton :icon="Icons.Delete" color="error" tooltip="Delete" />
          </ConfirmModal>
          <IconButton :icon="Icons.Edit" color="primary" tooltip="Edit" @click="() => onOpenEditUser(user.id)" />
          <IconButton :icon="Icons.Password" color="primary" tooltip="Manage Password" @click="() => onOpenManagePassword(user.id)" />
        </td>
      </tr>
    </tbody>
  </table>
  <div class="mt-2 w-full text-center">
    <PaginationControls @next="() => nextPage()" @prev="() => prevPage()" :current-page="activePage" :total-pages="totalPages" />
  </div>
</template>
