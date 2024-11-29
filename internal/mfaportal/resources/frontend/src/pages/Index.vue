<script setup lang="ts">
import { useInfoStore } from "@/store/info";

const info = useInfoStore()

</script>

<template>
      <template v-if="!info.isInfoLoading && !info.user.has_registered">
            <h4 class="card-title text-center mb-4">Register MFA Method</h4>
            <div v-if="info.user.available_mfa_methods.length > 0" v-for="method in info.user.available_mfa_methods">
            <button class="btn btn-primary w-full">{{ method.friendly_name }}</button>
            </div>
            <div v-else>No MFA methods, configured and enabled.</div>
      </template>

</template>
