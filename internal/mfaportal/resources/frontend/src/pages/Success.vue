<script setup lang="ts">
import { logout, getStatus, type StatusDTO } from '@/api';
import { useToastError } from '@/composables/useToastError';
import { useWebSocketStore } from '@/store/info';

import { ref, onMounted } from 'vue';

const sessionDetails = ref<StatusDTO | null>(null);
const info = useWebSocketStore()

const { catcher } = useToastError();

const isLoggingOut = ref(false);
const isLoadingDetails = ref(true); // Start as loading
const hasLoadedOnce = ref(false);

async function fetchSessionDetails() {
  try {
    isLoadingDetails.value = true;

    // Fetch status
    const statusResp = await getStatus()
    sessionDetails.value = statusResp
    hasLoadedOnce.value = true;

  } catch (e) {
    catcher(e, "Failed to fetch session details");
    sessionDetails.value = null
  } finally {
    isLoadingDetails.value = false;
  }
}

async function downloadStatus() {
  
  try {
    // Convert status data to JSON string
    const statusResp = await getStatus()

    const jsonData = JSON.stringify(statusResp, null, 2);
    
    // Create blob and download link
    const blob = new Blob([jsonData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    // Create temporary download link
    const link = document.createElement('a');
    link.style = "display: none";
    link.href = url;
    link.download = `debug-${new Date().toISOString().split('T')[0]}.json`;
    
    // Trigger download
    document.body.appendChild(link);
    link.click();
    
    // Cleanup
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  } catch (e) {
    catcher(e, "Failed to download status data");
  }
}

onMounted(async () => {
  // Trigger animations on mount
  document.querySelector('.auth-card')?.classList.add('slide-in');

  // Start loading details immediately
  await fetchSessionDetails();

  setTimeout(() => {
    document.querySelector('.content-section')?.classList.add('fade-in');
  }, 200);
});

async function doLogout() {
  try {
    isLoggingOut.value = true;
    const resp = await logout();
    if (!resp) {
      throw new Error("Failed to logout");
    }
    // Logout success logic would go here (like redirect)
  } catch (e) {
    catcher(e, "");
    isLoggingOut.value = false;
  }
}
</script>

<template>
  <div class="auth-card">
    <!-- Success Header -->
    <div class="text-center mb-8">
      <div class="flex items-center justify-center gap-3">
        <h1 class="text-3xl font-bold">Authorised</h1>
        <div class="w-12 h-12 bg-success/20 rounded-full flex items-center justify-center">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-success" fill="none" viewBox="0 0 24 24"
            stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
      </div>
    </div>

    <div class="content-section">
      <!-- Network Access Details - Always reserve space -->
      <div class="network-details-container mb-6">
        <!-- Loading State -->
        <div v-if="isLoadingDetails && !hasLoadedOnce"
          class="bg-gradient-to-r from-primary/10 to-primary/5 border border-primary/20 backdrop-blur-sm rounded-xl p-6">
          <div class="flex items-center gap-3 mb-4">
            <div class="w-8 h-8 bg-primary/20 rounded-lg flex items-center justify-center">
              <div class="loading loading-spinner loading-sm text-primary"></div>
            </div>
            <h4 class="font-semibold text-lg">Loading Access Details...</h4>
          </div>

          <!-- Skeleton placeholders -->
          <div class="space-y-6">
            <div class="skeleton-section">
              <div class="flex items-center gap-2 mb-3">
                <div class="w-2 h-2 bg-base-300 rounded-full animate-pulse"></div>
                <div class="h-4 bg-base-300 rounded w-16 animate-pulse"></div>
                <div class="h-5 bg-base-300 rounded w-6 animate-pulse"></div>
              </div>
              <div class="flex flex-wrap gap-2">
                <div class="h-8 bg-base-300 rounded-lg w-24 animate-pulse"></div>
                <div class="h-8 bg-base-300 rounded-lg w-32 animate-pulse"></div>
                <div class="h-8 bg-base-300 rounded-lg w-20 animate-pulse"></div>
              </div>
            </div>

            <div class="skeleton-section">
              <div class="flex items-center gap-2 mb-3">
                <div class="w-2 h-2 bg-base-300 rounded-full animate-pulse"></div>
                <div class="h-4 bg-base-300 rounded w-24 animate-pulse"></div>
                <div class="h-5 bg-base-300 rounded w-6 animate-pulse"></div>
              </div>
              <div class="flex flex-wrap gap-2">
                <div class="h-8 bg-base-300 rounded-lg w-28 animate-pulse"></div>
                <div class="h-8 bg-base-300 rounded-lg w-36 animate-pulse"></div>
              </div>
            </div>
          </div>
        </div>

        <!-- Loaded Content -->
        <div v-else-if="sessionDetails"
          class="bg-gradient-to-r from-primary/10 to-primary/5 border border-primary/20 backdrop-blur-sm rounded-xl p-6 transition-all duration-500 ease-out"
          :class="{ 'opacity-0': isLoadingDetails, 'opacity-100': !isLoadingDetails }">
          <h4 class="font-semibold mb-4 flex items-center justify-between text-lg">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 bg-primary/20 rounded-lg flex items-center justify-center">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-primary" fill="none" viewBox="0 0 24 24"
                  stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9v-9m0-9v9" />
                </svg>
              </div>
              Access Details
            </div>
            <div class="flex gap-2">
              <button @click="downloadStatus" :disabled="!sessionDetails || isLoadingDetails"
                class="btn btn-ghost btn-sm h-8 w-8 p-0 hover:bg-primary/10 transition-all duration-200"
                title="Download debug data">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </button>
              <button @click="fetchSessionDetails" :disabled="isLoadingDetails"
                class="btn btn-ghost btn-sm h-8 w-8 p-0 hover:bg-primary/10 transition-all duration-200"
                title="Refresh access details">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 transition-transform duration-300"
                  :class="{ 'animate-spin': isLoadingDetails }" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              </button>
            </div>
          </h4>

          <div class="space-y-6">
            <div v-if="sessionDetails?.Public?.length" class="resource-section">
              <div class="flex items-center gap-2 mb-3">
                <div class="w-2 h-2 bg-success rounded-full"></div>
                <span class="font-medium">Public Routes: {{ sessionDetails.Public.length }}</span>
              </div>
            </div>

            <div v-if="sessionDetails?.MFA?.length" class="resource-section">
              <div class="flex items-center gap-2 mb-3">
                <div class="w-2 h-2 bg-warning rounded-full"></div>
                <span class="font-medium">MFA Protected Routes: {{ sessionDetails.MFA.length }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Error State -->
        <div v-else-if="hasLoadedOnce && !sessionDetails"
          class="bg-gradient-to-r from-error/10 to-error/5 border border-error/20 backdrop-blur-sm rounded-xl p-6">
          <div class="flex items-center gap-3 mb-2">
            <div class="w-8 h-8 bg-error/20 rounded-lg flex items-center justify-center">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-error" fill="none" viewBox="0 0 24 24"
                stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.268 15.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
            </div>
            <h4 class="font-semibold text-lg">Failed to Load Network Details</h4>
          </div>
          <p class="text-sm opacity-70">Unable to fetch network access information.</p>
        </div>
      </div>

      <!-- Action Buttons -->
      <div class="flex flex-col gap-3">
        <button class="btn btn-secondary btn-lg group" @click="doLogout" :disabled="isLoggingOut">
          <span v-if="isLoggingOut" class="loading loading-spinner loading-sm mr-2"></span>
          <svg v-if="!isLoggingOut" xmlns="http://www.w3.org/2000/svg"
            class="h-5 w-5 mr-2 group-hover:translate-x-1 transition-transform duration-200" fill="none"
            viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
          </svg>
          {{ isLoggingOut ? 'Logging out...' : 'Logout' }}
        </button>
      </div>
      <div class="text-center mt-6">
        <p class="text-xs opacity-60 mt-2">{{ info.state.userInfo?.versions.wag }}</p>
      </div>
    </div>
  </div>
</template>

<style scoped>
.auth-card {
  opacity: 0;
  transform: translateY(20px);
  transition: all 0.6s cubic-bezier(0.4, 0, 0.2, 1);
}

.auth-card.slide-in {
  opacity: 1;
  transform: translateY(0);
}

.content-section {
  opacity: 0;
  transform: translateY(10px);
  transition: all 0.6s ease-out;
}

.content-section.fade-in {
  opacity: 1;
  transform: translateY(0);
}

.network-details-container {
  min-height: 200px;
  /* Reserve minimum space to prevent layout shifts */
}

.skeleton-section {
  padding: 0.2rem;
  border-radius: 0.75rem;
  background: hsl(var(--b2) / 0.1);
  border: 1px solid hsl(var(--b3) / 0.3);
}

.resource-section {
  padding: 0.2rem;
  border-radius: 0.75rem;
  background: hsl(var(--b2) / 0.3);
  border: 1px solid hsl(var(--b3) / 0.5);
}

.resource-badge {
  @apply px-3 py-1.5 rounded-lg text-sm font-medium transition-all duration-200 hover:scale-105;
  backdrop-filter: blur(4px);
}

.resource-badge.success {
  @apply bg-success/20 text-success border border-success/30;
}

.resource-badge.warning {
  @apply bg-warning/20 text-warning border border-warning/30;
}

.resource-badge.error {
  @apply bg-error/20 text-error border border-error/30;
}

.btn-lg {
  @apply h-14 text-base;
}

/* Enhanced button hover effects */
.btn:hover {
  transform: translateY(-1px);
  box-shadow: 0 8px 25px -8px hsl(var(--p) / 0.3);
}

.btn-outline:hover {
  box-shadow: 0 8px 25px -8px hsl(var(--bc) / 0.2);
}

/* Smooth transitions for all interactive elements */
.btn,
.resource-badge {
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
}

/* Skeleton animation refinements */
@keyframes pulse {

  0%,
  100% {
    opacity: 1;
  }

  50% {
    opacity: 0.5;
  }
}

.animate-pulse {
  animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}
</style>