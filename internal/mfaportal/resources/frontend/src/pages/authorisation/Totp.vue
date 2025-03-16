<script setup lang="ts">
import { computed, nextTick, ref, useTemplateRef } from "vue";
import { useToast } from "vue-toastification";

import PageLoading from "@/components/PageLoading.vue";

import { useApi } from "@/composables/useApi";
import { useToastError } from "@/composables/useToastError";

import {
  authoriseTotp,
  getTotpDetails,
  registerTotp,
  type TOTPDetailsDTO,
} from "@/api";
import router from "@/router";
import { useWebSocketStore } from "@/store/info";
import DigitInput from "@/components/DigitInput.vue";

const infoStore = useWebSocketStore();

const toast = useToast();
const { catcher } = useToastError();


async function authorise(code: string) {
  try {
    const resp = await authoriseTotp(code);

    if (!resp.status && resp.status == "error") {
      toast.error(resp.error ?? "Failed");
      return;
    } else {
      router.push("/success");
    }
  } catch (e) {
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
        <DigitInput execution-name="Verify" @submit="authorise"></DigitInput>
      </div>
  </template>
</template>
