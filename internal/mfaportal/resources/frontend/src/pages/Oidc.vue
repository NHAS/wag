<script setup lang="ts">
import { useToastError } from '@/composables/useToastError';
import { computed } from 'vue'
import { useRoute } from 'vue-router'
const { catcher } = useToastError();

const route = useRoute()

type AuthAction = "oidc_register" | "oidc_auth"

const authActionMap: Record<AuthAction, { text: string; apiEndpoint: string }> = {
  oidc_register: { text: "Register within your SSO", apiEndpoint: "/api/oidc/register" },
  oidc_auth: { text: "Sign in with SSO", apiEndpoint: "/api/oidc/authorise/start" }
}

const buttonText = computed(() => {
  const name = route.name as AuthAction
  return authActionMap[name]?.text || ""
})


async function doAuthorization() {
  try {
    const name = route.name as AuthAction
    const apiEndpoint = authActionMap[name]?.apiEndpoint || ""
    if (apiEndpoint === "") {
      throw new Error("No valid api route was retrieved");
    }
    window.location.href = apiEndpoint;
  } catch (e) {
    catcher(e, "Failed to authorise with IDP");
  }
}
</script>

<template>
  <!-- Header Section -->
  <h3 class="text-2xl font-bold text-center">Verify Your Identity</h3>
  <div class="divider my-1"></div>

  <!-- Description -->
  <p class="text-lg text-center mb-6">
    To access restricted resources, please verify your identity with your SSO provider.
  </p>

  <!-- Button section -->
  <div class="auth-card slide-in">
    <div class="content-section fade-in">
      <button @click="doAuthorization" class="btn btn-primary btn-lg w-full">
        {{ buttonText }}
      </button>
    </div>
    </div>
</template>
