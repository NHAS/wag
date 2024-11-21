<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  isOpen: boolean
}>()

const emit = defineEmits(['update:isOpen'])

const isOpen = computed({
  get: () => props.isOpen,
  set: (value: boolean) => emit('update:isOpen', value)
})
</script>

<template>
  <div :class="isOpen ? 'modal modal-open' : 'modal'">
    <form method="dialog" class="remove-card-backgrounds modal-box">
      <button @click="() => (isOpen = false)" class="btn btn-circle btn-ghost btn-sm absolute right-2 top-2">✕</button>
      <slot></slot>
    </form>
    <form method="dialog" class="modal-backdrop">
      <button @click="() => (isOpen = false)">close</button>
    </form>
  </div>
</template>

<style scoped>
.modal-box {
  max-width: 90vw;
  width: auto;
}
/* .modal::backdrop { */
/* background-color: rgba(0, 0, 0, 0.3); */
/* animation: modal-pop 0.2s ease-out; */
/* } */
</style>

<style>
.modal-box.remove-card-backgrounds .card {
  box-shadow: none !important;
}
</style>
