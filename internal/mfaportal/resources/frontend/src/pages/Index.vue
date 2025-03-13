<script setup lang="ts">
import { useWebSocketStore } from "@/store/info";

const info = useWebSocketStore();
</script>

<template>
  <template v-if="!info.isLoading && !info.isRegistered">
    <h4 class="card-title text-center mb-4">Register MFA Method</h4>
    <template v-if="info.availableMfaMethods.length > 0">
      <div
        v-for="method in info.availableMfaMethods"
        :key="'mfa-' + method.method"
      >
        <button class="btn btn-primary w-full">
          {{ method.friendly_name }}
        </button>
      </div>
    </template>
    <div v-else>No MFA methods, configured and enabled.</div>
  </template>
</template>
