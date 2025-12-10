<script setup lang="ts">
import { login } from '@/api';
import { useToastError } from '@/composables/useToastError';
import { useWebSocketStore } from '@/store/info';
const { catcher } = useToastError();

const info = useWebSocketStore()

async function doLogin() {
  try {
    const resp = await login();
    if (!resp) {
      throw new Error("Failed to login");
    }
    // Login success logic
    if (info.state.userInfo) {
    info.state.userInfo.is_authorized = resp
    } else {
      console.warn('userInfo is null, cannot update is_authorized')
    }
  } catch (e) {
    catcher(e, "");
  }
}
</script>
<template>
  <h4 class="card-title text-center mb-4">
    Authorize this device
  </h4>
  <div class="flex flex-col gap-3 items-center">
      <button @click="doLogin" class="btn btn-secondary btn-lg group flex items-center">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          class="h-5 w-5 mr-2 group-hover:translate-x-1 transition-transform duration-200"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
          />
        </svg>
        Authorize
      </button>
  </div>
</template>
