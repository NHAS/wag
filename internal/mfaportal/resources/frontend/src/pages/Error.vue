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
  // dont use router here as we want pretty much every single move to be governed by App.vue
  window.location.href = "/"
}

</script>

<template>
  <h4 class="card-title w-full text-center justify-center">Error Occurred!</h4>
  <p>If this continues to occur please contact {{ info.helpMail }}</p>


  <div class="text-center mb-4">
    <p class="text-error font-bold">{{ props.errorCode || '500' }}</p>
    <p>{{ props.errorMessage || "Something went wrong. Please try again later." }}</p>
  </div>
  
  <div class="w-full flex justify-center gap-4">
    <button class="btn btn-error w-32" @click="goHome">Home</button>
  </div>
</template>