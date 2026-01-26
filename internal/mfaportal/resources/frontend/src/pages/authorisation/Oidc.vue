<script setup lang="ts">

async function signIn() {
  window.location.href = "/api/oidc/authorise/start";
}

</script>

<template>
 <!-- Header Section -->
  <h3 class="text-2xl font-bold text-center">Verify Your Identity</h3>

  <p class="text-lg text-center mb-6">
    Sign in to to access restricted resources.
  </p>

  <div class="divider my-1"></div>

  <button @click="signIn" class="btn btn-primary btn-lg w-full">
    Sign In
  </button>
</template>
