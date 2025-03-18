<script setup lang="ts">

setTimeout(function(){
  window.location.href = "/api/oidc/authorise/start"
}, 1500)

</script>

<template>
  <h4 class="card-title text-center">
    Redirecting you to your SSO provider...
    <span class="ml-4 loading loading-spinner loading-lg"></span>
  </h4>
</template>
