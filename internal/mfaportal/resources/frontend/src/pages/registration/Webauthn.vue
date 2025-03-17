<script setup lang="ts">
import { finaliseWebauthnRegistration, getRegistrationWebauthnDetails } from "@/api";
import WebAuthnInput from "@/components/WebAuthnInput.vue";
import { useToastError } from "@/composables/useToastError";
import router from "@/router";
import { useWebSocketStore } from "@/store/info";
import { useToast } from "vue-toastification";

const infoStore = useWebSocketStore();

const toast = useToast();
const { catcher } = useToastError();

// Base64 to ArrayBuffer
function bufferDecode(value: string) {
  return Uint8Array.from(atob(value.replace(/_/g, '/').replace(/-/g, '+')), c => c.charCodeAt(0));
}

async function register() {
  try {
    const credentialCreationOptions = await getRegistrationWebauthnDetails();

    if (credentialCreationOptions.status === undefined) {
      toast.error(credentialCreationOptions.error ?? "Failed");
      return;
    }

    if (credentialCreationOptions.status === "error") {
      toast.error(credentialCreationOptions.error ?? "Failed");
      return;
    }

    const creds = credentialCreationOptions.data

    console.log(creds)

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
      toast.error("Failed to get credentials from security key")
      return
    }

    const resp = await finaliseWebauthnRegistration(newCreds)
    if (resp.status !== undefined) {
      toast.error(resp.error ?? "Failed");
      return;
    }

    if (resp.status !== "success") {
      toast.error(resp.error ?? "Failed");
      return;
    }

    router.push("/success")
  } catch (e: any) {
    console.log(e, e.lineNumber)
    catcher(e, "");
  }
}
</script>

<template>
<WebAuthnInput @submit="register" :help-mail="infoStore.helpMail" title="Verify" button-label="Verify"></WebAuthnInput>
</template>