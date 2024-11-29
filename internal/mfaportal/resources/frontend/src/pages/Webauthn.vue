<script setup lang="ts">
import { useInfoStore } from "@/store/info";

const infoStore = useInfoStore();
</script>

<template>
  <h4 class="card-title text-center">Insert security key</h4>
  <div>
    <p class="mb-8">
      In order to access restricted resources you must verify your identity.
      Please insert your security key. If you are encountering issues, please
      send an email to
      <a :href="'mailto:' + infoStore.user.helpmail">{{
        infoStore.user.helpmail
      }}</a>
    </p>
    <button class="btn btn-primary w-full" autofocus>
      Authorise <font-awesome-icon :icon="['fa-solid', 'key']" />
    </button>
  </div>
</template>
