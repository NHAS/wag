<script setup lang="ts">
import { RouterView } from "vue-router";

import { useWebSocketStore } from "./store/info";
import { onBeforeUnmount, onMounted } from "vue";

const infoStore = useWebSocketStore();

onMounted( () => {
  infoStore.connect();
});

onBeforeUnmount(() => {
  infoStore.cleanup();
});

</script>

<template>
  <main class="w-full min-h-screen">
    <div class="bg-slate-200 min-h-screen flex items-center justify-center p-4">
      <div
        class="card bg-neutral shadow-xl max-w-3xl h-max text-neutral-content"
      >
        <div class="card-body">
          <RouterView v-if="infoStore.state.isConnected" />
          <div v-else>
            <span class="flex items-center gap-4"
              >Loading details...
              <span class="loading loading-spinner loading-lg"></span
            ></span>
          </div>
        </div>
      </div>
    </div>
  </main>
</template>
