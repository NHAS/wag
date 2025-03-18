<script setup lang="ts">
import { authoriseWebAuthn, finaliseWebauthnRegistration, getAuthorisationWebauthnDetails, getRegistrationWebauthnDetails } from "@/api";
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

async function authorise() {
  try {
    const credentialRequestOptions = await getAuthorisationWebauthnDetails();

    if (credentialRequestOptions.status === undefined) {
      toast.error(credentialRequestOptions.error ?? "Failed");
      return;
    }

    if (credentialRequestOptions.status === "error") {
      toast.error(credentialRequestOptions.error ?? "Failed");
      return;
    }

    const creds = credentialRequestOptions.data

    creds.publicKey.challenge = bufferDecode(creds.publicKey.challenge);
    creds.publicKey.allowCredentials.forEach(function (listItem: any) {
      listItem.id = bufferDecode(listItem.id);
    });

    const newCreds = await navigator.credentials.get({
      publicKey: creds.publicKey,
    }) as PublicKeyCredential

    if (newCreds == null) {
      toast.error("Failed to get credentials from security key")
      return
    }

    const resp = await authoriseWebAuthn(newCreds)
    if (resp.status === undefined) {
      toast.error(resp.error ?? "Failed, unknown server response.");
      return;
    }

    if (resp.status !== "success") {
      toast.error(resp.error ?? "Failed");
      return;
    }

  } catch (e: any) {
    console.log(e, e.lineNumber)
    catcher(e, "");
  }
}
</script>

<template>
  <WebAuthnInput @submit="authorise" :help-mail="infoStore.helpMail" title="Verify Your Identity"
    button-label="Verify with Security Key"></WebAuthnInput>
</template>