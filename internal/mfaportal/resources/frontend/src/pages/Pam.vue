<script setup lang="ts">
import { useInfoStore } from "@/store/info";

const infoStore = useInfoStore();
</script>

<template>
  <h4 class="card-title text-center">Enter Password</h4>

  <div class="max-w-[400px]">
    <p>
      In order to access restricted resources you must verify your identity.
      Please ente r your credentials below. If you are encountering issues,
      please send an email to
      <a :href="'mailto:' + infoStore.user.helpmail">{{
        infoStore.user.helpmail
      }}</a>
    </p>
    <label class="label font-bold text-neutral-content mb-2 mt-2">
      <input
        type="password"
        class="input input-bordered text-neutral w-full"
        autofocus
        placeholder="************"
      />
    </label>
    <button class="btn btn-primary w-full">Submit</button>
  </div>
</template>
