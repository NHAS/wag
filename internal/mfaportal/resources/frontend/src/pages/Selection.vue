<script setup lang="ts">
import { useWebSocketStore } from "@/store/info";

const info = useWebSocketStore();
</script>

<template>
  <template v-if="info.isConnected">

    <template v-if="info.availableMfaMethods.length == 0">
      <div>No MFA methods, configured and enabled.</div>
    </template>

    <template v-else>
      <template v-if="!info.isRegistered">
        <h4 class="text-2xl font-bold text-center mb-4">Register</h4>
        <div v-for="method in info.availableMfaMethods" :key="'mfa-' + method.method">
          <RouterLink :to="'/register/' + method.method">
            <button class="btn btn-primary w-full">
              {{ method.friendly_name }}
            </button>
          </RouterLink>
        </div>

      </template>
      <template v-else>
        <h4 class="text-2xl font-bold text-center mb-4">Authorise</h4>
        <div v-for="method in info.availableMfaMethods" :key="'mfa-' + method.method">
          <RouterLink :to="'/authorise/' + method.method">
            <button class="btn btn-primary w-full">
              {{ method.friendly_name }}
            </button>
          </RouterLink>
        </div>

      </template>

    </template>

  </template>
  <template v-else>
    <div>
      <span class="flex items-center gap-4">Loading details...
        <span class="loading loading-spinner loading-lg"></span></span>
    </div>
  </template>
</template>
