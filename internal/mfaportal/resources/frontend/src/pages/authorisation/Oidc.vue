<script setup lang="ts">
import { useToastError } from '@/composables/useToastError';

const { catcher } = useToastError();

async function doSignIn() {
  try {
    window.location.href = "/api/oidc/authorise/start";
  } catch (e) {
    catcher(e, "Failed to authorise with IDP");
  } 
}
</script>

<template>
  <div class="auth-card slide-in">
    <div class="text-center mb-8">
      <h1 class="text-2xl font-bold">Access your account securely</h1>
      <p class="text-sm opacity-70">Authenticate with your SSO provider to continue</p>
    </div>

    <div class="content-section fade-in">
      <button @click="doSignIn" class="btn btn-primary btn-lg w-full">
        Sign in with SSO
      </button>
    </div>
  </div>
</template>