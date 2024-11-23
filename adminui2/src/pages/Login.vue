<script setup lang="ts">
import { ref, watch, computed } from 'vue'
import { storeToRefs } from 'pinia'
import { useRouter } from 'vue-router'
import { useToast } from 'vue-toastification'
import { useToastError } from '@/composables/useToastError'
import HrOr from '@/components/HrOr.vue'

import { useAuthStore } from '@/stores/auth'

import { Icons } from '@/util/icons'
import { changePassword } from '@/api'

const authStore = useAuthStore()
const router = useRouter()
const toast = useToast()

const { hasCompletedAuth, loginError, isLoginLoading, loggedInUser } = storeToRefs(authStore)

enum ActiveScreens {
  FirstStep,
  PasswordChange,
  Done
}

const activeScreen = computed(() => {
  if (loggedInUser.value == null) {
    return ActiveScreens.FirstStep
  }

  if(loggedInUser.value.change) {
    return ActiveScreens.PasswordChange
  }

  return ActiveScreens.Done
})

if (hasCompletedAuth.value) {
  router.push('/dashboard')
}

watch(hasCompletedAuth, hasCompletedAuth => {
  if (hasCompletedAuth) {
    router.push('/dashboard')
  }
})

const username = ref('')
const password = ref('')

async function doCredentialLogin(event: Event) {
  if (event) {
    event.preventDefault()
  }

  authStore.login(username.value, password.value)
}

async function startOIDCLogin() {
  window.location.href = '/login/oidc'
}

const cardTitle = computed(() => {
  switch (activeScreen.value) {
    case ActiveScreens.FirstStep:
      return 'Login to Wag'

    case ActiveScreens.PasswordChange:
      return 'Set a new password'

    case ActiveScreens.Done:
      return 'You have successfully logged in!'

    default:
      return ''
  }
})

const { catcher } = useToastError()
const isPasswordChangeLoading = ref(false)
const newPassword = ref('')
async function doPasswordChange(event: Event) {
  if (event) {
    event.preventDefault()
  }

  try {
    isPasswordChangeLoading.value = true
    const res = await changePassword({
      current_password: password.value,
      new_password: newPassword.value
    })
    if (res.success) {
      toast.success('Password changed successfully')
    } else {
      toast.warning('Failed to change password: ' + res.message)
    }

    authStore.refreshAuth()
  } catch (e: any) {
    catcher(e, 'Failed to change temporary password. ')
  } finally {
    isPasswordChangeLoading.value = false
  }
}


</script>

<template>
  <main class="z-10 flex min-h-screen items-center justify-center self-center bg-neutral">
    <div class="card w-96 bg-base-100 shadow-xl">
      <div class="card-body">
        <div class="card-title justify-center">
          <h2>{{ cardTitle }}</h2>
        </div>

        <div v-if="activeScreen == ActiveScreens.FirstStep">
          <form @submit="doCredentialLogin">
            <div v-if="loginError != null" class="my-2 text-center text-red-500">
              <p>{{ loginError }}</p>
            </div>
            <div class="form-control">
              <label class="label">
                <span class="label-text">Username</span>
              </label>
              <input type="text" placeholder="john.doe" class="input input-bordered" v-model="username" />
            </div>
            <div class="form-control">
              <label class="label">
                <span class="label-text">Password</span>
              </label>
              <input type="password" placeholder="hunter2" class="input input-bordered" v-model="password" />
            </div>
            <div class="form-control mt-6">
              <button type="submit" class="btn btn-primary" :disabled="isLoginLoading">
                <span class="loading loading-spinner loading-md" v-if="isLoginLoading"></span>
                Login
              </button>
            </div>
          </form>

          <HrOr class="my-4" v-if="true" />

          <div class="form-control" v-if="true">
            <button class="btn btn-primary" @click="startOIDCLogin" :disabled="isLoginLoading">Login with SSO</button>
          </div>
        </div>

        <div v-if="activeScreen == ActiveScreens.PasswordChange">
          <p class="text-center">You are required to change your password</p>
          <form @submit="doPasswordChange">
            <div class="form-control">
              <label class="label">
                <span class="label-text">Old Password</span>
              </label>
              <input type="password" placeholder="hunter2" class="input input-bordered" v-model="password" />
            </div>
            <div class="form-control">
              <label class="label">
                <span class="label-text">New Password</span>
              </label>
              <input type="password" placeholder="hunter2" class="input input-bordered" v-model="newPassword" />
            </div>
            <div v-if="loginError != null" class="mt-4 text-center text-red-500">
              <p>{{ loginError }}</p>
            </div>
            <div class="form-control mt-6">
              <button type="submit" class="btn btn-primary" :disabled="isPasswordChangeLoading">
                <span class="loading loading-spinner loading-md" v-if="isLoginLoading"></span>
                Change Password
              </button>
            </div>
          </form>
        </div>

        <div v-if="activeScreen == ActiveScreens.Done" class="text-center">
          <p>Welcome</p>
          <font-awesome-icon :icon="Icons.Tick" class="my-8 text-success" style="font-size: 5rem" />
        </div>
      </div>
    </div>
  </main>
</template>
