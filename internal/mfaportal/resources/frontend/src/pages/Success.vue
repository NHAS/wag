<script setup lang="ts">
import { logout } from '@/api';
import { useToastError } from '@/composables/useToastError';
import { useWebSocketStore } from '@/store/info';
import { useToast } from 'vue-toastification';
import { ref, onMounted } from 'vue';

const toast = useToast();
const { catcher } = useToastError();
const info = useWebSocketStore();

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
      toast.error("Failed to logout");
      isLoggingOut.value = false;
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
    <div class="card-body items-center text-center">
      <h2 class="card-title text-2xl font-bold mb-2">Welcome Back!</h2>
      <p class="text-base-content/70 mb-6">You've been successfully authenticated</p>
      
      <div class="checkmark-container">
        <div class="w-24 h-24 bg-success rounded-full flex items-center justify-center checkmark-circle">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-success-content" fill="none" viewBox="0 0 24 24"
            stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
          </svg>
        </div>
      </div>
      
      <div class="user-info mt-6 mb-6">
        <div class="badge badge-primary badge-lg">{{ info.username }}</div>
        <p class="text-sm mt-2 text-base-content/70">Logged in successfully</p>
      </div>
      
      <div class="card-actions justify-center mt-2">
        <button 
          class="btn btn-primary btn-wide" 
          @click="doLogout"
          :disabled="isLoggingOut"
        >
          <span v-if="isLoggingOut" class="loading loading-spinner loading-xs mr-2"></span>
          {{ isLoggingOut ? 'Logging Out...' : 'Logout' }}
        </button>
      </div>
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

.user-info {
  transition: all 0.3s ease;
}

.user-info:hover {
  transform: translateY(-2px);
}

.btn-wide {
  min-width: 12rem;
}
</style>