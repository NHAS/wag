<script setup lang="ts">
import { useWebSocketStore } from "@/store/info";

const info = useWebSocketStore();
</script>

<template>
  <h4 class="card-title w-full text-center justify-center">Locked</h4>
  <p>
    Your device is locked. Please contact {{ info.helpMail }} for resolution.
  </p>
</template>
