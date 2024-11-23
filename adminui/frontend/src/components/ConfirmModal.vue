<script setup lang="ts">
import { ref } from 'vue'

const props = defineProps<{
  title?: string
  body?: string
}>()

const title = props.title ?? 'Confirm'
const body = props.body ?? 'Are you sure you want to proceed? You might not be able to undo this action.'

const emit = defineEmits(['onConfirm'])
const isOpen = ref(false)

function confirm() {
  isOpen.value = false
  emit('onConfirm')
}
</script>

<template>
  <div :class="isOpen ? 'modal modal-open' : 'modal'">
    <form method="dialog" class="remove-card-backgrounds modal-box text-left">
      <button @click="() => (isOpen = false)" class="btn btn-circle btn-ghost btn-sm absolute right-2 top-2">✕</button>
      <h2 class="my-4 font-mono text-xl font-bold">{{ title }}</h2>
      <p class="font-mono">{{ body }}</p>

      <div class="modal-action">
        <button class="btn m-1" @click="() => (isOpen = false)">Cancel</button>
        <button class="btn btn-error m-1" @click="() => confirm()">Proceed</button>
      </div>
    </form>
    <form method="dialog" class="modal-backdrop">
      <button @click="() => (isOpen = false)">close</button>
    </form>
  </div>
  <span @click="() => (isOpen = true)">
    <slot></slot>
  </span>
</template>

<style scoped>
.modal-box {
  max-width: 90vw;
  width: auto;
}
</style>

<style>
.modal-box.remove-card-backgrounds .card {
  box-shadow: none !important;
}
</style>
