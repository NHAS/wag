<script setup lang="ts">
import { ref } from "vue";

import WebAuthnInput from "@/components/WebAuthnInput.vue";

import { useToastError } from "@/composables/useToastError";

import { authoriseWebAuthn, getAuthorisationWebauthnDetails } from "@/api";
import { useWebSocketStore } from "@/store/info";

const infoStore = useWebSocketStore();

const { catcher } = useToastError();

const isLoading = ref(false);

// Base64 to ArrayBuffer
function bufferDecode(value: string) {
  return Uint8Array.from(
    atob(value.replace(/_/g, "/").replace(/-/g, "+")),
    (c) => c.charCodeAt(0),
  );
}

async function authorise() {
  isLoading.value = true;
  try {
    const credentialRequestOptions = await getAuthorisationWebauthnDetails();

    if (credentialRequestOptions.status === undefined) {
      throw new Error(credentialRequestOptions.error ?? "Failed");
    }

    if (credentialRequestOptions.status === "error") {
      throw new Error(credentialRequestOptions.error ?? "Failed");
    }

    const creds = credentialRequestOptions.data;

    creds.publicKey.challenge = bufferDecode(creds.publicKey.challenge);
    creds.publicKey.allowCredentials.forEach(function (listItem: any) {
      listItem.id = bufferDecode(listItem.id);
    });

    const newCreds = (await navigator.credentials.get({
      publicKey: creds.publicKey,
    })) as PublicKeyCredential;

    if (newCreds == null) {
      throw new Error("Failed to get credentials from security key");
    }

    const resp = await authoriseWebAuthn(newCreds);
    if (resp.status === undefined) {
      throw new Error(resp.error ?? "Failed, unknown server response.");
    }

    if (resp.status !== "success") {
      throw new Error(resp.error ?? "Failed");
    }
  } catch (e: any) {
    isLoading.value = false;

    console.log(e, e.lineNumber);
    catcher(e, "");
  }
}
</script>

<template>
  <WebAuthnInput
    @submit="authorise"
    :help-mail="infoStore.helpMail"
    title="Verify Your Identity"
    :loading="isLoading"
    button-label="Verify with Security Key"
  ></WebAuthnInput>
</template>
