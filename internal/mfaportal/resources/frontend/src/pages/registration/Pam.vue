<script setup lang="ts">
import { ref } from "vue";

import PamInput from "@/components/PamInput.vue";

import { useToastError } from "@/composables/useToastError";

import { registerPam } from "@/api";
import { useWebSocketStore } from "@/store/info";

const infoStore = useWebSocketStore();

const { catcher } = useToastError();

const isLoading = ref(false);

async function register(password: string) {
  isLoading.value = true;
  try {
    const resp = await registerPam(password);

    if (!resp.status && resp.status == "error") {
      throw new Error(resp.error ?? "Failed");
    }
  } catch (e) {
    isLoading.value = false;
    catcher(e, "");
  }
}
</script>

<template>
  <PamInput
    @submit="register"
    :help-mail="infoStore.helpMail"
    :loading="isLoading"
  ></PamInput>
  <router-link
    to="/selection"
    v-if="infoStore.availableMfaMethods.length > 1"
    class="flex-1"
  >
    <button class="btn btn-neutral w-full">Use Another Method</button>
  </router-link>
</template>
