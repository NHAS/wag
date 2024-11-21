<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { watch } from 'vue'
import { useRouter } from 'vue-router'

import { useAuthStore } from '@/stores/auth'

const router = useRouter()

const authStore = useAuthStore()
const { loginError, loggedInUser } = storeToRefs(authStore)

// If, on page load, we have URL parameters that include "state" and "code", then we're handling an OIDC callback
const qsParams = new URLSearchParams(window.location.search)
const qsParamKeys = [...qsParams.keys()]
const isSSOCallback = qsParamKeys.includes('state') && qsParamKeys.includes('code')

if (isSSOCallback) {
  authStore.handleOIDCCallback(window.location.search)
} else {
  // We're on the wrong page, direct back to login
  router.push('/')
}

// We redirect back to /login to complete MFA if its required, and to then show the welcome tick
watch(loggedInUser, newLoggedInUser => {
  if (newLoggedInUser != null) {
    router.push('/login')
  }
})
</script>

<template>
  <main class="z-10 flex min-h-screen items-center justify-center self-center bg-neutral">
    <div class="card w-96 bg-base-100 shadow-xl">
      <div class="card-body" v-if="loginError == null">
        <div class="card-title justify-center">
          <h2>Logging you in...</h2>
        </div>

        <div class="my-8 text-center">
          <span class="loading loading-spinner loading-lg"></span>
        </div>
      </div>

      <div class="card-body" v-if="loginError != null">
        <div class="card-title justify-center">
          <h2>Error</h2>
        </div>

        <div class="my-8 text-center">
          <div class="my-2 text-center text-red-500">
            <p>{{ loginError }}</p>
          </div>
        </div>
      </div>
    </div>
  </main>
</template>
