<script setup lang="ts">
const props = defineProps<{
  text: string
  icon?: string
}>()
</script>

<template>
  <div class="text-center text-slate-400 p-4 w-full">
    <p>{{ props.text }}</p>
    <p v-if="props.icon != null" class="text-xl mt-1">
      <font-awesome-icon :icon="props.icon" />
    </p>
  </div>
</template>
