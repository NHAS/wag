<script setup lang="ts">
import { useThemeStore } from '@/store/theme';
import { computed } from 'vue';

const themeStore = useThemeStore();

const themeIcon = computed(() => {
  switch (themeStore.preference) {
    case 'light':
      return ['fas', 'sun'];
    case 'dark':
      return ['fas', 'moon'];
    case 'system':
      return ['fas', 'circle-half-stroke'];
    default:
      return ['fas', 'circle-half-stroke'];
  }
});

const tooltipText = computed(() => {
  switch (themeStore.preference) {
    case 'light':
      return 'Light theme';
    case 'dark':
      return 'Dark theme';
    case 'system':
      return 'System theme';
    default:
      return 'Toggle theme';
  }
});

const handleClick = () => {
  themeStore.cycleTheme();
};
</script>

<template>
  <div class="theme-toggle-container">
    <button
      @click="handleClick"
      class="btn btn-ghost btn-sm btn-circle theme-toggle-button"
      :aria-label="`Switch theme (current: ${tooltipText})`"
      :title="tooltipText"
    >
      <font-awesome-icon
        :icon="themeIcon"
        class="theme-icon"
        size="lg"
      />
    </button>
  </div>
</template>

<style scoped>
.theme-toggle-container {
  position: fixed;
  top: 1rem;
  right: 1rem;
  z-index: 50;
}

.theme-toggle-button {
  transition: transform 0.2s ease, background-color 0.2s ease;
}

.theme-toggle-button:hover {
  transform: scale(1.1);
}

.theme-toggle-button:active {
  transform: scale(0.95);
}

.theme-icon {
  transition: transform 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);
}

.theme-toggle-button:hover .theme-icon {
  transform: rotate(20deg);
}

.theme-toggle-button:active .theme-icon {
  transform: rotate(0deg);
}

/* Smooth color transitions */
.theme-toggle-button {
  will-change: transform;
}
</style>
