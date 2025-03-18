<script setup lang="ts">
import { logout } from '@/api';
import { useToastError } from '@/composables/useToastError';
import router from '@/router';
import { useWebSocketStore } from '@/store/info';
import { watch } from 'vue';
import { useToast } from 'vue-toastification';

const toast = useToast()
const { catcher } = useToastError();

const info = useWebSocketStore()

async function doLogout() {
  try {
    const resp = await logout();

    if (!resp) {
      toast.error("Failed to logout");
      return;
    } 

    router.push("/");
  } catch (e) {
    catcher(e, "");
  }
}


if (!info.isLoggedIn || !info.isRegistered || !info.isConnected) {
  router.push("/")
}

watch(info, async newState => {
  if (!newState.isLoggedIn || !newState.isRegistered || !newState.isConnected) {
    router.push("/")
  }
})

</script>

<template>
  <h4 class="card-title w-full text-center justify-center">Authorised!</h4>

  <div class="max-w-[300px] min-w-[300px] w-full flex justify-center">
    <div class="w-32 h-32 bg-success rounded-full flex items-center justify-center mb-4 mt-4 checkmark">
      <svg xmlns="http://www.w3.org/2000/svg" class="h-28 w-28 text-success-content" fill="none" viewBox="0 0 24 24"
        stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M5 13l4 4L19 7"
          class="text-neutral-content" />
      </svg>
    </div>
  </div>

  <div class="w-full flex justify-center gap-4">
    <button class="btn btn-primary w-32" @click="() => doLogout()">Logout</button>
  </div>
</template>

<style scoped>
@keyframes slideDown {
  0% {
    transform: translateY(-100%);
    opacity: 0;
  }

  100% {
    transform: translateY(0);
    opacity: 1;
  }
}

@keyframes checkmark {
  0% {
    transform: scale(0);
  }

  50% {
    transform: scale(1.2);
  }

  100% {
    transform: scale(1);
  }
}

.slide-down {
  animation: slideDown 0.5s ease-out forwards;
}

.checkmark {
  animation: checkmark 0.5s ease-out 0.5s forwards;
}
</style>
