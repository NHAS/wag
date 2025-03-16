<script setup lang="ts">
import router from "@/router";
import PamInput from "@/components/PamInput.vue";

import { useToast } from "vue-toastification";
import { authorisePam } from "@/api";
import { useToastError } from "@/composables/useToastError";
import { useWebSocketStore } from "@/store/info";

const infoStore = useWebSocketStore();

const toast = useToast();
const { catcher } = useToastError();

async function authorise(password: string) {
  try {
    const resp = await authorisePam(password);

    if (!resp.status && resp.status == "error") {
      toast.error(resp.error ?? "Failed");
      return;
    } else {
      router.push("/success");
    }
  } catch (e) {
    catcher(e, "");
  }
};

</script>

<template>
  <PamInput @submit="authorise" :help-mail="infoStore.helpMail"></PamInput>
</template>
