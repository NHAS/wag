<script setup lang="ts">
import { useInfoStore } from "@/store/info";

const info = useInfoStore();
</script>

<template>
  <template v-if="!info.isInfoLoading && !info.user.has_registered">
    <h4 class="card-title text-center mb-4">Register MFA Method</h4>
    <template v-if="info.user.available_mfa_methods.length > 0">
      <div
        v-for="method in info.user.available_mfa_methods"
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
