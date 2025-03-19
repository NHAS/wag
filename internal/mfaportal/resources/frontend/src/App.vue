<script setup lang="ts">
import { RouterView } from "vue-router";

import { useWebSocketStore } from "./store/info";
import { onBeforeMount, onBeforeUnmount, watch, nextTick } from "vue";
import router from "./router";

const info = useWebSocketStore();

onBeforeMount(() => {
  info.connect();
});

onBeforeUnmount(() => {
  info.cleanup();
});

async function determinePath() {
  try {
    await nextTick()

    if (info.isDeviceLocked || info.isAccountLocked) {
      console.log("detemined locked")
      router.push("/locked")
      return
    }

    if (info.isAuthorised) {
      console.log("detemined authed")

      router.push("/success")
      return
    }

    const path = info.isRegistered ? '/authorise/' : '/register/';

    if (info.availableMfaMethods.length == 1) {
      console.log("detemined", path + info.availableMfaMethods[0].method)

      router.push(path + info.availableMfaMethods[0].method)
    } else if (info.selectedMFAMethod !== "unset") {
      console.log("detemined", path + info.selectedMFAMethod)

      router.push(path + info.selectedMFAMethod)
    } else if (info.defaultMFAMethod != "") {
      console.log("default")
      router.push(path + info.defaultMFAMethod)
    } else {
      console.log("selection")
      router.push("/selection")
    }
  } catch (error) {
    console.error('Navigation error:', error);
  }
}

// if we've already magically connected 
if (info.isConnected) {
  determinePath()
}

// Set a watch to change the application state on any new updates
watch(info, async newState => {
  if (newState.isConnected) {
    console.log("state changed: ", newState.state)
    determinePath()
  }
})

</script>

<template>
  <main class="w-full min-h-screen">
    <div class="bg-slate-200 min-h-screen flex items-center justify-center p-4">
      <div class="card bg-neutral shadow-xl max-w-3xl h-max text-neutral-content">
        <div class="card-body">
          <RouterView />
        </div>
      </div>
    </div>
  </main>
</template>
