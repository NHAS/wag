<script setup lang="ts">
const props = defineProps<{
  currentPage: number
  totalPages?: number
}>()

const emit = defineEmits(['next', 'prev'])
</script>

<template>
  <div class="join">
    <button class="btn join-item btn-sm cursor-pointer" @click="() => emit('prev')">«</button>
    <button class="btn join-item btn-sm">
      Page {{ props.currentPage + 1 }}{{ props.totalPages != null && props.totalPages > 1 ? ` of ${props.totalPages}` : '' }}
    </button>
    <button class="btn join-item btn-sm cursor-pointer" @click="() => emit('next')">»</button>
  </div>
</template>
