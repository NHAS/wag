<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  modelValue: {
    [key: string]: boolean
  }
}>()

const entries = computed(() => Object.entries(props.modelValue))

const emit = defineEmits(['update:modelValue'])

function toggleValue(key: string) {
  const newValue = {
    ...props.modelValue,
    [key]: !props.modelValue[key]
  }

  emit('update:modelValue', newValue)
  return !props.modelValue[key]
}
</script>

<template>
  <div>
    <div v-for="[key, value] in entries" :key="key">
      <label class="label cursor-pointer">
        <span class="label-text">{{ key }}</span>
        <input
          type="checkbox"
          :checked="value"
          :value="value"
          class="checkbox"
          @click="
            e => {
              e.stopPropagation()
              toggleValue(key)
            }
          "
        />
      </label>
    </div>
  </div>
</template>
