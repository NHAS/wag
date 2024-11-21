<script setup lang="ts">
import { computed } from 'vue'

import { maskCharsets } from '@/util/hashcat'

const props = defineProps<{
  modelValue: string
}>()

const emit = defineEmits(['update:modelValue'])

const effectiveLength = computed(() => {
  const mask = props.modelValue
  const withDummies = mask.replace(/\?[a-zA-Z]/g, 'z')

  return withDummies.length
})

const value = computed({
  get: () => props.modelValue,
  set: (value: string) => emit('update:modelValue', value)
})
</script>

<template>
  <label class="label pl-0 font-bold">Enter Mask</label>
  <input type="text" placeholder="Mask" v-model="value" class="input input-bordered w-full max-w-xs" />
  <p class="text-xs mt-1">Length: {{ effectiveLength }}</p>
  <div class="mt-4">
    <span
      class="tooltip tooltip-bottom"
      :data-tip="`${maskCharset.description}`"
      v-for="maskCharset in maskCharsets"
      :key="maskCharset.mask"
    >
      <button text="foo" @click="value += maskCharset.mask" class="btn btn-outline btn-xs mr-1 normal-case">
        {{ maskCharset.mask }}
      </button>
    </span>
  </div>
</template>
