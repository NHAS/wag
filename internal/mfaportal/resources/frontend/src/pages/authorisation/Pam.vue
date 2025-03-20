<script setup lang="ts">
import router from "@/router";
import PamInput from "@/components/PamInput.vue";

import { useToast } from "vue-toastification";
import { authorisePam } from "@/api";
import { useToastError } from "@/composables/useToastError";
import { useWebSocketStore } from "@/store/info";
import { ref } from "vue";

const infoStore = useWebSocketStore();

const { catcher } = useToastError();

const isLoading = ref(false)

async function authorise(password: string) {
  isLoading.value = true
  try {
    const resp = await authorisePam(password);

    if (!resp.status && resp.status == "error") {
     throw new Error(resp.error ?? "Failed");
    } 
  } catch (e) {
    isLoading.value = false
    catcher(e, "");
  }
};

</script>

<template>
  <PamInput @submit="authorise" :help-mail="infoStore.helpMail" :loading="isLoading"></PamInput>
</template>
