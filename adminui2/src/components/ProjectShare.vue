<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { computed, ref } from 'vue'
import { useToast } from 'vue-toastification'

import SearchableDropdown from '@/components/SearchableDropdown.vue'
import IconButton from '@/components/IconButton.vue'

import { addProjectShare, deleteProjectShare, getProjectShares } from '@/api/groups'
import type { UserDTO } from '@/api/types'

import { useApi } from '@/composables/useApi'
import { useToastError } from '@/composables/useToastError'

import { useAuthStore } from '@/stores/auth'
import { useUsersStore } from '@/stores/users'

import { Icons } from '@/util/icons'

const props = defineProps<{
  projectId: string
}>()

const { data, silentlyRefresh: refreshShares } = useApi(() => getProjectShares(props.projectId))

const authStore = useAuthStore()
const { loggedInUser } = storeToRefs(authStore)
const userStore = useUsersStore()
const { users } = storeToRefs(userStore)

const usersSharedWith = computed(() => {
  if (data.value == null) {
    return []
  }

  return data.value.user_ids
})

const tableRows = computed(() => {
  if (data.value == null) {
    return []
  }

  return data.value.user_ids.map(id => userStore.byId(id)).filter(x => x != null) as UserDTO[]
})

const dropdownUsers = computed(() => {
  return users.value
    ?.filter(x => x.id != loggedInUser.value?.id && usersSharedWith.value.every(y => x.id !== y))
    .map(x => ({
      text: x.username,
      value: x.id
    }))
})

const userIdToShare = ref('')

const toast = useToast()
const { catcher } = useToastError()

async function onAddShare() {
  if (userIdToShare.value === '') {
    return
  }

  try {
    const user_id = userIdToShare.value
    await addProjectShare(props.projectId, {
      user_id
    })
    toast.info('Shared project with ' + (userStore.byId(user_id)?.username ?? 'Unknown user'))
  } catch (e: any) {
    catcher(e)
  } finally {
    userIdToShare.value = ''
    refreshShares()
  }
}

async function onDeleteShare(user: UserDTO) {
  try {
    await deleteProjectShare(props.projectId, user.id)
    toast.info('Removed access from ' + user.username)
  } catch (e: any) {
    catcher(e)
  } finally {
    refreshShares()
  }
}
</script>

<template>
  <div class="min-h-[400px]">
    <h2 class="mx-12 mb-8 text-center text-xl font-bold">Share this project</h2>
    <div class="form-control mb-4 h-max">
      <label class="label font-bold">
        <span class="label-text">Choose user</span>
      </label>
      <div class="flex min-w-[400px] justify-between">
        <SearchableDropdown
          v-model="userIdToShare"
          :options="dropdownUsers"
          placeholderText="Select someone to share with..."
          class="flex-grow"
        />
        <button class="btn btn-primary ml-1" @click="onAddShare">Share</button>
      </div>
    </div>
    <div class="mt-8" v-if="usersSharedWith.length > 0">
      <label class="label pl-0 font-bold">
        <span class="label-text">Users you've shared this project with</span>
      </label>
      <table class="compact-table table table-sm w-full">
        <thead>
          <tr>
            <th>Username</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(user, i) in tableRows" :key="user.id + i">
            <td class="w-full">{{ user?.username }}</td>
            <td class="text-center">
              <IconButton :icon="Icons.Remove" color="error" tooltip="Remove" @click="() => onDeleteShare(user)" />
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div class="mt-8 text-center" v-else>You have not shared this project with anyone yet.</div>
  </div>
</template>
