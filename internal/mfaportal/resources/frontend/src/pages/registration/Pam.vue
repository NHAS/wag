<script setup lang="ts">
import router from "@/router";
import PamInput from "@/components/PamInput.vue";

import { useToast } from "vue-toastification";
import { registerPam } from "@/api";
import { useToastError } from "@/composables/useToastError";
import { useWebSocketStore } from "@/store/info";

const infoStore = useWebSocketStore();

const toast = useToast();
const { catcher } = useToastError();

async function register(password: string) {
  try {
    const resp = await registerPam(password);

    if (!resp.status && resp.status == "error") {
      toast.error(resp.error ?? "Failed");
      return;
    }
  } catch (e) {
    catcher(e, "");
  }
};

</script>

<template>
  <PamInput @submit="register" :help-mail="infoStore.helpMail"></PamInput>
  <router-link to="/selection" v-if="infoStore.availableMfaMethods.length > 1" class="flex-1">
    <button class="btn btn-neutral btn-outline w-full">Use Another Method</button>
  </router-link>
</template>
