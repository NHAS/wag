<script setup lang="ts">
import { logout } from '@/api';
import { useToastError } from '@/composables/useToastError';
import { useWebSocketStore } from '@/store/info';
import { useToast } from 'vue-toastification';
import { ref, onMounted } from 'vue';

const toast = useToast();
const { catcher } = useToastError();

const isLoggingOut = ref(false);

onMounted(() => {
  // Trigger animations on mount
  document.querySelector('.auth-card')?.classList.add('slide-in');
  setTimeout(() => {
    document.querySelector('.checkmark-container')?.classList.add('appear');
  }, 300);
});

async function doLogout() {
  try {
    isLoggingOut.value = true;
    const resp = await logout();
    if (!resp) {
      throw new Error("Failed to logout");
      return;
    }
    // Logout success logic would go here (like redirect)
  } catch (e) {
    catcher(e, "");
    isLoggingOut.value = false;
  }
}
</script>

<template>

    <h2 class="text-center text-2xl font-bold mb-2">Welcome</h2>
    <p class="text-sm text-center mb-6">You have successfully authenticated</p>

    <div class="checkmark-container flex items-center justify-center text-center">
      <div class="w-24 h-24 bg-success items-center justify-center rounded-full flex checkmark-circle">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-success-content" fill="none" viewBox="0 0 24 24"
          stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
        </svg>
      </div>
    </div>

    <div class="card-actions justify-center mt-2">
      <button class="btn btn-primary w-full" @click="doLogout" :disabled="isLoggingOut">
        <span v-if="isLoggingOut" class="loading loading-spinner loading-xs mr-2"></span>
        {{ isLoggingOut ? 'Logging Out...' : 'Logout' }}
      </button>
    </div>

</template>

<style scoped>
.checkmark-container {
  opacity: 0;
  transform: scale(0.8);
  transition: all 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
  margin: 1.5rem 0;
}

.checkmark-container.appear {
  opacity: 1;
  transform: scale(1);
}

.checkmark-circle {
  position: relative;
  box-shadow: 0 0 0 15px rgba(72, 187, 120, 0.1);
}

.checkmark-circle::before {
  content: '';
  position: absolute;
  inset: -8px;
  border-radius: 50%;
  background: rgba(72, 187, 120, 0.2);
  z-index: -1;
}

</style>