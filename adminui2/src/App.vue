<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useToast } from 'vue-toastification'
import { onMounted, watch } from 'vue'
import { RouterView, useRouter } from 'vue-router'

import { useAuthStore } from '@/stores/auth'
import { useDevicesStore } from '@/stores/devices'
import { useUsersStore } from '@/stores/users'

const router = useRouter()
const authStore = useAuthStore()
const devicesStore = useDevicesStore()
const usersStore = useUsersStore()

const { hasCompletedAuth, hasTriedAuth, loggedInUser, isLoggedIn } = storeToRefs(authStore)

const toast = useToast()

onMounted(async () => {
  await router.isReady()

  router.beforeEach(() => {
    authStore.refreshAuth()
  })

  authStore.refreshAuth()
})

watch(hasCompletedAuth, (newHasCompletedAuth, prevHasCompletedAuth) => {
  if (newHasCompletedAuth && !prevHasCompletedAuth) {
    toast.success(`Welcome ${loggedInUser.value?.username}`)
    devicesStore.load(true)
    usersStore.load(true)
  }
})

watch(isLoggedIn, (newIsLoggedIn, oldIsLoggedIn) => {
  // We've been logged out
  if (oldIsLoggedIn && !newIsLoggedIn) {
    router.push('/')
  }
})

// When we try to refresh auth for the first time (after page load)
// check to see if we're logged in our not
// if we're not logged in, go to login page
watch(hasTriedAuth, (newHasTriedAuth, oldHasTriedAuth) => {
  if (newHasTriedAuth && !oldHasTriedAuth && router.currentRoute.value.path != '/oidc-callback') {
    if (!isLoggedIn.value) {
      router.push('/')
    }
  }
})
</script>

<template>
  <RouterView />
</template>
