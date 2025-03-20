<script setup lang="ts">
import { useToast } from "vue-toastification";
import { useToastError } from "@/composables/useToastError";

import {
  authoriseTotp,
} from "@/api";
import router from "@/router";
import { useWebSocketStore } from "@/store/info";
import DigitInput from "@/components/DigitInput.vue";
import { ref } from "vue";

const infoStore = useWebSocketStore();

const { catcher } = useToastError();

const isLoading = ref(false)


async function authorise(code: string) {
  isLoading.value = true
  try {
    const resp = await authoriseTotp(code);

    if (!resp.status && resp.status == "error") {
      throw new Error(resp.error ?? "Failed");
    } 
  } catch (e) {
    isLoading.value = false
    catcher(e, "");
  }
}

</script>

<template>
  <template v-if="infoStore.isRegistered">
      <h3 class="text-2xl font-bold text-center mb-4">Verify Your Identity</h3>
      <div class="max-w-[400px] mx-auto">
        <p class="text-center">
          Please enter your MFA code to access restricted resources. Having trouble?
          <a :href="'mailto:' + infoStore.helpMail" class="link link-primary">Contact support</a>.
        </p>
        <DigitInput execution-name="Verify" @submit="authorise" :loading="isLoading"></DigitInput>
      </div>
  </template>
</template>
