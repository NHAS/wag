<script setup lang="ts">
import { finaliseWebauthnRegistration, getRegistrationWebauthnDetails } from "@/api";
import WebAuthnInput from "@/components/WebAuthnInput.vue";
import { useToastError } from "@/composables/useToastError";
import router from "@/router";
import { useWebSocketStore } from "@/store/info";
import { ref } from "vue";
import { useToast } from "vue-toastification";

const infoStore = useWebSocketStore();

const toast = useToast();
const { catcher } = useToastError();

// Base64 to ArrayBuffer
function bufferDecode(value: string) {
  return Uint8Array.from(atob(value.replace(/_/g, '/').replace(/-/g, '+')), c => c.charCodeAt(0));
}

const isLoading = ref(false)

async function register() {
  isLoading.value = true
  try {
    const credentialCreationOptions = await getRegistrationWebauthnDetails();

    if (credentialCreationOptions.status === undefined) {
      throw new Error(credentialCreationOptions.error ?? "Failed");
    }

    if (credentialCreationOptions.status === "error") {
      throw new Error(credentialCreationOptions.error ?? "Failed");
    }

    const creds = credentialCreationOptions.data
    creds.publicKey.challenge = bufferDecode(creds.publicKey.challenge);
    creds.publicKey.user.id = bufferDecode(creds.publicKey.user.id);
    if (creds.publicKey.excludeCredentials) {
      for (var i = 0; i < creds.publicKey.excludeCredentials.length; i++) {
        creds.publicKey.excludeCredentials[i].id = bufferDecode(creds.publicKey.excludeCredentials[i].id);
      }
    }

    const newCreds = await navigator.credentials.create({
      publicKey: creds.publicKey as PublicKeyCredentialCreationOptions,
    }) as PublicKeyCredential

    if (newCreds == null) {
      throw new Error("Failed to get credentials from security key")
    }

    const resp = await finaliseWebauthnRegistration(newCreds)
    if (resp.status === undefined) {
      throw new Error(resp.error ?? "Failed");
    }

    if (resp.status !== "success") {
      throw new Error(resp.error ?? "Failed");
    }

    // if we get here we're effectively waiting on a notification from the backend that auth was a success, so load forever
  } catch (e: any) {
    isLoading.value = false
    console.log(e, e.lineNumber)
    catcher(e, "");
  }
}
</script>

<template>
  <WebAuthnInput @submit="register" :help-mail="infoStore.helpMail" title="Verify" button-label="Verify" :loading=isLoading>
  </WebAuthnInput>
  <router-link to="/selection" v-if="infoStore.availableMfaMethods.length > 1" class="flex-1">
    <button class="btn btn-neutral btn-outline w-full">Use Another Method</button>
  </router-link>

</template>