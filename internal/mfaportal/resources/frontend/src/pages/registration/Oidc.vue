<script setup lang="ts">

setTimeout(function(){
  window.location.href = "/api/oidc/register"
}, 750)

</script>

<template>
  <h4 class="card-title text-center">
    Redirecting you to your SSO provider to register...
    <span class="ml-4 loading loading-spinner loading-lg"></span>
  </h4>
</template>
