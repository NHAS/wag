<script setup lang="ts">
import { useRoute } from "vue-router";

import { useWebSocketStore } from "@/store/info";

const info = useWebSocketStore();
const route = useRoute();

const errorMessage =
  (route.query.m as string) || "Something went wrong. Please try again later.";

function goHome() {
  // dont use router here as we want pretty much every single move to be governed by App.vue
  window.location.href = "/";
}
</script>

<template>
  <div class="flex flex-col items-center justify-center space-y-6 py-8">
    <!-- Error Icon -->
    <div class="relative">
      <div
        class="w-20 h-20 bg-error/20 rounded-full flex items-center justify-center"
      >
        <svg
          class="w-10 h-10 text-error"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
          />
        </svg>
      </div>
      <div
        class="absolute -top-1 -right-1 w-6 h-6 bg-error rounded-full flex items-center justify-center"
      >
        <span class="text-error-content text-sm font-bold">!</span>
      </div>
    </div>

    <!-- Error Title -->
    <div class="text-center space-y-2">
      <h1 class="text-3xl font-bold text-error">Something went wrong</h1>
    </div>

    <!-- Error Message -->
    <div
      class="bg-error/10 border border-error/20 rounded-lg p-4 max-w-md w-full"
    >
      <div class="flex items-start space-x-3">
        <div class="flex-1">
          <p class="text-sm font-medium text-error">Details</p>
          <p class="text-sm opacity-90 mt-1 break-words">{{ errorMessage }}</p>
        </div>
      </div>
    </div>

    <!-- Action Buttons -->
    <div class="flex flex-col sm:flex-row gap-3 w-full max-w-sm">
      <button class="btn btn-primary flex-1 gap-2" @click="goHome">
        <svg
          class="w-4 h-4"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
          />
        </svg>
        Try Again
      </button>
    </div>

    <!-- Contact Information -->
    <div
      class="text-center space-y-2 pt-4 border-t border-base-300 w-full max-w-md"
    >
      <p class="text-sm opacity-70">Need help? Contact support</p>
      <a
        :href="'mailto:' + info.helpMail"
        class="inline-flex items-center gap-2 text-primary hover:text-primary-focus transition-colors duration-200 text-sm font-medium"
      >
        {{ info.helpMail }}
      </a>
    </div>
  </div>
</template>
