import { defineStore } from 'pinia';
import { ref, computed, watch } from 'vue';

export type ThemePreference = 'light' | 'dark' | 'system';
export type ResolvedTheme = 'corporate' | 'business';

const STORAGE_KEY = 'wag-theme-preference';
const LIGHT_THEME = 'corporate';
const DARK_THEME = 'business';

export const useThemeStore = defineStore('theme', () => {
  const preference = ref<ThemePreference>('system');
  const systemTheme = ref<'light' | 'dark'>('light');

  const resolvedTheme = computed<ResolvedTheme>(() => {
    if (preference.value === 'system') {
      return systemTheme.value === 'dark' ? DARK_THEME : LIGHT_THEME;
    }
    return preference.value === 'dark' ? DARK_THEME : LIGHT_THEME;
  });

  const themePreference = window.matchMedia('(prefers-color-scheme: dark)');

  const updateSystemTheme = () => {
    systemTheme.value = themePreference.matches ? 'dark' : 'light';
  };

  updateSystemTheme();

  themePreference.addEventListener('change', updateSystemTheme);

  const loadPreference = () => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored === 'light' || stored === 'dark' || stored === 'system') {
        preference.value = stored;
      }
    } catch (error) {
      console.error('Failed to load theme preference:', error);
    }
  };

  const savePreference = () => {
    try {
      localStorage.setItem(STORAGE_KEY, preference.value);
    } catch (error) {
      console.error('Failed to save theme preference:', error);
    }
  };

  const applyTheme = () => {
    document.documentElement.setAttribute('data-theme', resolvedTheme.value);
  };

  const setPreference = (newPreference: ThemePreference) => {
    preference.value = newPreference;
    savePreference();
    applyTheme();
  };

  const cycleTheme = () => {
    const cycle: ThemePreference[] = ['light', 'dark', 'system'];
    const currentIndex = cycle.indexOf(preference.value);
    const nextIndex = (currentIndex + 1) % cycle.length;
    setPreference(cycle[nextIndex]);
  };

  watch([preference, systemTheme], () => {
    applyTheme();
  });

  const handleStorageChange = (event: StorageEvent) => {
    if (event.key === STORAGE_KEY && event.newValue) {
      const newValue = event.newValue;
      if (newValue === 'light' || newValue === 'dark' || newValue === 'system') {
        preference.value = newValue;
      }
    }
  };

  window.addEventListener('storage', handleStorageChange);

  const initialize = () => {
    loadPreference();
    applyTheme();
  };

  const cleanup = () => {
    themePreference.removeEventListener('change', updateSystemTheme);
    window.removeEventListener('storage', handleStorageChange);
  };

  return {
    preference,
    systemTheme,
    resolvedTheme,
    setPreference,
    cycleTheme,
    initialize,
    cleanup,
  };
});
