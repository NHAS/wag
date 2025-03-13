<script setup lang="ts">
import { useWebSocketStore } from "@/store/info";

const infoStore = useWebSocketStore();
</script>

<template>
  <h4 class="card-title text-center">Insert security key</h4>
  <div>
    <p class="mb-8">
      In order to access restricted resources you must verify your identity.
      Please insert your security key. If you are encountering issues, please
      send an email to
      <a :href="'mailto:' + infoStore.helpMail">{{
        infoStore.helpMail
      }}</a>
    </p>
    <button class="btn btn-primary w-full" autofocus>
      Authorise <font-awesome-icon :icon="['fa-solid', 'key']" />
    </button>
  </div>
</template>
