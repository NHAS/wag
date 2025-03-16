<script setup lang="ts">
import { computed, nextTick, ref, useTemplateRef } from "vue";
import { useToast } from "vue-toastification";

import PageLoading from "@/components/PageLoading.vue";

import { useApi } from "@/composables/useApi";
import { useToastError } from "@/composables/useToastError";

import {
  getTotpDetails,
  registerTotp,
  type TOTPDetailsDTO,
} from "@/api";
import router from "@/router";
import { useWebSocketStore } from "@/store/info";
import DigitInput from "@/components/DigitInput.vue";

const infoStore = useWebSocketStore();

const { data: registration, isLoading: isLoadingTotpRegistrationDetails } = useApi(() =>
  getTotpDetails(),
);

const isLoadingRegistrationDetails = computed(() => {
  return isLoadingTotpRegistrationDetails.value;
});

const totpDetails = computed(() => registration.value ?? ({} as TOTPDetailsDTO));

const showManualEntry = ref(false)

const toast = useToast();
const { catcher } = useToastError();



async function register(code: string) {
  try {
    const resp = await registerTotp(code);

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
  <PageLoading v-if="isLoadingRegistrationDetails"></PageLoading>
  <template v-else>
    <h3 class="text-2xl font-bold text-center mb-8">Set Up Two-Factor Authentication</h3>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
      <!-- Left side - Instructions -->
      <div class="space-y-4">
        <h4 class="font-bold text-lg">Setup Instructions:</h4>
        <ul class="steps steps-vertical">
          <li class="step step-primary">Install Google Authenticator</li>
          <li class="step step-primary">Tap + and choose "Scan a QR code"</li>
          <li class="step step-primary">Scan the QR code</li>
          <li class="step step-primary">Enter the 6-digit code below</li>
        </ul>
      </div>

      <!-- Right side - QR Code -->
      <div class="flex flex-col items-center justify-center md:mt-12">
        <div class="bg-white p-2 rounded-lg shadow-md">
          <img class="w-[240px] h-[240px]" :src="totpDetails.image_data" alt="QR Code" />
        </div>
        <button class="btn btn-sm btn-ghost mt-2" @click="showManualEntry = !showManualEntry">
          {{ showManualEntry ? 'Hide Manual Entry' : 'Cant Scan?' }}
        </button>
      </div>
    </div>

    <div v-if="showManualEntry" class="mt-4 mb-2 bg-base-200 p-4 rounded-lg text-base-content">
      <p class="mb-2 text-sm" ref="toast">
        Manually enter these details:
      </p>
      <div class="grid grid-cols-2 gap-2 text-sm">
        <div class="font-semibold">Type of key:</div>
        <div>Time based</div>

        <div class="font-semibold">Account name:</div>
        <div class="font-mono bg-base-300 px-2 py-1 rounded text-base-content">{{ totpDetails.account_name }}</div>

        <div class="font-semibold">Your key:</div>
        <div class="font-mono bg-base-300 px-2 py-1 rounded overflow-x-auto text-base-content">{{ totpDetails.key }}
        </div>
      </div>
    </div>

    <DigitInput execution-name="Verify & Complete Setup" @submit="register"></DigitInput>

    <router-link to="/" v-if="infoStore.availableMfaMethods.length > 1" class="flex-1">
      <button class="btn btn-outline w-full">Use Another Method</button>
    </router-link>
  </template>
</template>
