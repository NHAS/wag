<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { onMounted, watch } from 'vue'
import { RouterView, useRouter } from 'vue-router'
import { POSITION, useToast } from 'vue-toastification'

import { type NotificationDTO } from './api'
import { useSessionsStore } from './stores/sessions'

import { useAuthStore } from '@/stores/auth'
import { useDevicesStore } from '@/stores/devices'
import { useUsersStore } from '@/stores/users'

const router = useRouter()
const authStore = useAuthStore()
const devicesStore = useDevicesStore()
const sessionsStore = useSessionsStore()
const usersStore = useUsersStore()

const { hasCompletedAuth, hasTriedAuth, isLoggedIn } = storeToRefs(authStore)

const toast = useToast()

const httpsEnabled = window.location.protocol == 'https:'

function connectNotificationsWebsocket() {
  const notificationsSocket = new WebSocket((httpsEnabled ? 'wss://' : 'ws://') + window.location.host + '/api/notifications')
  notificationsSocket.onmessage = function (msg) {
    const notf = JSON.parse(msg.data) as NotificationDTO
    console.log(notf)
    toast(notf.message.join('\n'), {
      position: POSITION.TOP_RIGHT,
      pauseOnFocusLoss: true,
      onClick: function () {
        if (notf.url.length != 0) {
          if (notf.open_new_tab) {
            window.open(notf.url, '_blank')
            return
          }
          router.push(notf.url)
        }
      }
    })
  }

  notificationsSocket.onerror = function (err) {
    console.error('Notifications websocket encountered error: ', err, 'Closing socket')
    notificationsSocket.close()
  }
}

onMounted(async () => {
  await router.isReady()

  router.beforeEach(() => {
    authStore.refreshAuth()
  })

  authStore.refreshAuth()
})

watch(hasCompletedAuth, (newHasCompletedAuth, prevHasCompletedAuth) => {
  if (newHasCompletedAuth && !prevHasCompletedAuth) {
    sessionsStore.load(true)
    devicesStore.load(true)
    usersStore.load(true)
    connectNotificationsWebsocket()
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
