<script setup lang="ts">
import router from "@/router";
import { useWebSocketStore } from "@/store/info";
import { watch } from "vue";
import { useToast } from "vue-toastification";

const toast = useToast();
const info = useWebSocketStore();

function determinePath() {
  try {
    if (info.isDeviceLocked || info.isAccountLocked) {
      router.push("/locked")
      return
    }

    if (info.isAuthorised) {
      router.push("/success")
      return
    }

    const path = info.isRegistered ? '/authorise/' : '/register/';

    if (info.availableMfaMethods.length == 1) {
      router.push(path + info.availableMfaMethods[0].method)
    } else if (info.selectedMFAMethod !== "unset") {
      router.push(path + info.selectedMFAMethod)
    } else if (info.defaultMFAMethod != "") {
      router.push(path + info.defaultMFAMethod)
    } else {
      router.push("/selection")
    }
  } catch (error) {
    console.error('Navigation error:', error);
    toast.error("Failed to navigate. This is a UI bug please report it.")
  }
}

if (info.isConnected) {
  determinePath()
} else {
  watch(info, async newState => {
    if (newState.isConnected) {
      determinePath()
    }
  })
}

</script>

<template>
  <template v-if="!info.isConnected">
    <div>
      <span class="flex items-center gap-4">Loading...
        <span class="loading loading-spinner loading-lg"></span></span>
    </div>
  </template>
</template>
