<script setup lang="ts">
import { useWebSocketStore } from "@/store/info";

const info = useWebSocketStore();

// Add some helper functions for better UX
const getMethodIcon = (methodType: string) => {
  switch (methodType.toLowerCase()) {
    case 'totp':
      return ['fas', 'mobile-screen'];
    case 'oidc':
      return ['fas', 'sign-in'];
    case 'pam':
      return ['fas', 'computer'];
    case 'webauthn':
      return ['fas', 'key'];
    default:
      return ['fas', 'shield-check'];
  }
};


</script>

<template>
  <template v-if="info.isConnected">

    <template v-if="info.availableMfaMethods.length == 0">
      <h4 class="mb-2 text-center">No MFA methods, configured and enabled.</h4>
      <div>Please contact your administrator <a :href="'mailto:'+info.helpMail">{{ info.helpMail }}</a></div>
    </template>

    <template v-else>
      <h4 class="text-2xl font-bold text-center mb-4"> {{ !info.isRegistered ? 'Register Authentication Method' : 'Sign In' }}</h4>

      <p class="text-gray-300 mb-2 text-center">
        {{ !info.isRegistered
          ? 'Please select a multi-factor authentication method'
          : 'Choose an authentication method to continue' }}
      </p>
      <div v-for="method in info.availableMfaMethods" :key="'mfa-' + method.method" class="mt-2">
        <RouterLink :to="(!info.isRegistered ? '/register/' : '/authorise/') + method.method">
          <button class="btn btn-primary w-full">
            <font-awesome-icon :icon="getMethodIcon(method.method)" />
            {{ method.friendly_name }}
          </button>
        </RouterLink>
      </div>
    </template>

  </template>
  <template v-else>
    <div>
      <span class="flex items-center gap-4">Loading details...
        <span class="loading loading-spinner loading-lg"></span></span>
    </div>
  </template>
</template>