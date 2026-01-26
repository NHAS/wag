<script setup lang="ts">

async function register() {
  window.location.href = "/api/oidc/register";
}


</script>

<template>
  <!-- Header Section -->
  <h3 class="text-2xl font-bold text-center">Register Your Identity</h3>

  <p class="text-lg text-center mb-6">
    To access restricted resources, please register your identity with your single sign on provider.
  </p>

  <div class="divider my-1"></div>

  <button @click="register" class="btn btn-primary btn-lg w-full">
    Register
  </button>

</template>
