<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  rows?: string
  modelValue: string
}>()

const emit = defineEmits(['update:modelValue'])

const rows = props.rows ?? '3'

const rules = computed({
  get: () => props.modelValue,
  set: (value: string) => emit('update:modelValue', value)
})
</script>

<template>
  <textarea class="rules-input textarea textarea-bordered w-full font-mono" :rows="rows" v-model="rules"></textarea>
</template>

<style scoped>
textarea.rules-input {
  margin-top: 0;
  white-space: pre;
}
</style>
