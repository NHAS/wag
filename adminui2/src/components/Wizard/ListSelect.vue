<script setup lang="ts">
import { watch } from 'vue'

import type { DeviceDTO } from '@/api/types'

const props = defineProps<{
  labelText: string
  list: DeviceDTO[]
  modelValue: string[] // list of selected IDs
  limit: number
}>()

const emit = defineEmits(['update:modelValue'])

function constrainAndEmit(arr: string[]) {
  if (arr.length > props.limit) {
    emit('update:modelValue', arr.slice(arr.length - props.limit))
  } else {
    emit('update:modelValue', arr)
  }
}

if (props.modelValue.length > props.limit) {
  constrainAndEmit(props.modelValue)
}

watch(
  () => props.modelValue,
  newVal => {
    if (newVal.length > props.limit) {
      constrainAndEmit(newVal)
    }
  }
)

watch(
  () => props.limit,
  newLimit => {
    if (newLimit < props.modelValue.length) {
      constrainAndEmit(props.modelValue)
    }
  }
)

function toggleSelected(id: string) {
  if (props.modelValue.includes(id)) {
    constrainAndEmit(props.modelValue.filter(x => x != id))
  } else {
    constrainAndEmit([...props.modelValue, id])
  }
}
</script>

<template>
  <label class="label font-bold">{{ labelText }}</label>
  <table class="compact-table table w-full">
    <tbody>
      <tr>
        <td>Select</td>
        <td>Name</td>
        <td>Number of lines</td>
      </tr>
      <tr v-for="file in props.list" :key="file.id" @click="toggleSelected(file.id)" class="cursor-pointer">
        <td>
          <input
            v-if="props.limit > 1"
            type="checkbox"
            class="checkbox checkbox-xs align-middle"
            :class="props.modelValue.includes(file.id) ? 'checkbox-primary' : ''"
            :checked="props.modelValue.includes(file.id)"
          />
          <input
            v-else
            type="radio"
            class="radio radio-xs align-middle"
            :class="props.modelValue.includes(file.id) ? 'radio-primary' : ''"
            :checked="props.modelValue.includes(file.id)"
          />
        </td>
        <td>{{ file.name }}</td>
        <td>{{ file.lines }}</td>
      </tr>
    </tbody>
  </table>
</template>
