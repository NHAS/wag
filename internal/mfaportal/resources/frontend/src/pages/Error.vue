<script setup lang="ts">
import { useRouter } from 'vue-router';
import { useWebSocketStore } from '@/store/info';

const info = useWebSocketStore();
const router = useRouter();

// Optional: You can pass an error message as a prop
const props = defineProps<{
  errorMessage?: string;
  errorCode?: number;
}>();

function goHome() {
  router.push("/");
}

</script>

<template>
  <h4 class="card-title w-full text-center justify-center">Error Occurred!</h4>
  <p>If this continues to occur please contact {{ info.helpMail }}</p>
  <div class="max-w-[300px] min-w-[300px] w-full flex justify-center">
    <div
      class="w-32 h-32 bg-error rounded-full flex items-center justify-center mb-4 mt-4 error-icon"
    >
      <svg
        xmlns="http://www.w3.org/2000/svg"
        class="h-28 w-28 text-error-content"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1"
          d="M6 18L18 6M6 6l12 12"
          class="text-neutral-content"
        />
      </svg>
    </div>
  </div>
  
  <div class="text-center mb-4">
    <p class="text-error font-bold">{{ props.errorCode || '500' }}</p>
    <p>{{ props.errorMessage || "Something went wrong. Please try again later." }}</p>
  </div>
  
  <div class="w-full flex justify-center gap-4">
    <button class="btn btn-error w-32" @click="goHome">Home</button>
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

@keyframes errorAnimation {
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

.error-icon {
  animation: errorAnimation 0.5s ease-out 0.5s forwards;
}
</style>