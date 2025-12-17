<script setup lang="ts">
import { ref } from "vue";

import PamInput from "@/components/PamInput.vue";

import { useToastError } from "@/composables/useToastError";

import { authorisePam } from "@/api";
import { useWebSocketStore } from "@/store/info";

const infoStore = useWebSocketStore();

const { catcher } = useToastError();

const isLoading = ref(false);

async function authorise(password: string) {
  isLoading.value = true;
  try {
    const resp = await authorisePam(password);

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
    @submit="authorise"
    :help-mail="infoStore.helpMail"
    :loading="isLoading"
  ></PamInput>
</template>
