<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { ref, computed } from 'vue'
import { useToast } from 'vue-toastification'

import { accountChangePassword } from '@/api/account'

import { useToastError } from '@/composables/useToastError'

import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()
const { loggedInUser } = storeToRefs(authStore)

const changePasswordCurrentPassword = ref('')
const changePasswordNewPassword = ref('')
const changePasswordConfirmPassword = ref('')

const changePasswordValidationErrors = computed(() => {
  if (changePasswordNewPassword.value.length < 16) {
    return 'Password must be 16 characters minimum'
  }

  if (changePasswordNewPassword.value != changePasswordConfirmPassword.value) {
    return 'New passwords must match'
  }

  return null
})

const toast = useToast()
const { catcher } = useToastError()

const isChangePasswordLoading = ref(false)

async function onChangePassword() {
  if (changePasswordValidationErrors.value != null) {
    return
  }

  isChangePasswordLoading.value = true

  try {
    await accountChangePassword({
      new_password: changePasswordNewPassword.value,
      current_password: changePasswordCurrentPassword.value
    })
    toast.success('Password changed')
  } catch (e: any) {
    catcher(e)
  } finally {
    isChangePasswordLoading.value = false
  }
}
</script>

<template>
  <main class="w-full p-4">
    <h1 class="text-4xl font-bold">Welcome {{ loggedInUser?.username }}</h1>
    <div class="mt-6 flex flex-wrap gap-6">
      <div class="card bg-base-100 shadow-xl" v-if="!loggedInUser?.is_password_locked">
        <div class="card-body">
          <h2 class="card-title">Change Password</h2>

          <div class="form-control">
            <label class="label font-bold">
              <span class="label-text">Current Password</span>
            </label>
            <input
              v-model="changePasswordCurrentPassword"
              type="password"
              placeholder="hunter2"
              class="input input-bordered w-full max-w-xs"
            />
          </div>

          <div class="form-control">
            <label class="label font-bold">
              <span class="label-text">New Password</span>
            </label>
            <input v-model="changePasswordNewPassword" type="password" placeholder="hunter2" class="input input-bordered w-full max-w-xs" />
          </div>

          <div class="form-control">
            <label class="label font-bold">
              <span class="label-text">Confirm Password</span>
            </label>
            <input
              v-model="changePasswordConfirmPassword"
              type="password"
              placeholder="hunter2"
              class="input input-bordered w-full max-w-xs"
            />
          </div>

          <span class="tooltip mt-2 w-full" :data-tip="changePasswordValidationErrors">
            <button
              type="submit"
              class="btn btn-primary w-full"
              :disabled="changePasswordValidationErrors != null"
              @click="() => onChangePassword()"
            >
              <span class="loading loading-spinner loading-md" v-if="isChangePasswordLoading"></span>
              Change Password
            </button>
          </span>
        </div>
      </div>
      <div class="card bg-base-100 shadow-xl" v-else>
        <div class="card-body">
          <p>Your account is externally managed and you cannot set a password.</p>
        </div>
      </div>
    </div>
  </main>
</template>
