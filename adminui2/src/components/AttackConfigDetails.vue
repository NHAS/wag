<script setup lang="ts">
import { computed } from 'vue'

import type { HashcatParams } from '@/api/types'

import { useListfilesStore } from '@/stores/devices'

import { modeHasMask } from '@/util/hashcat'

const props = defineProps<{
  hashcatParams: HashcatParams
  isDistributed?: boolean
}>()

const listfileStore = useListfilesStore()

listfileStore.load()
function listfileName(id: string): string {
  return listfileStore.byId(id)?.name ?? 'Unknown'
}

const extraOptionsStr = computed(() => {
  const params = props.hashcatParams
  const arr = []

  if (params.optimized_kernels) {
    arr.push('Optimized kernels')
  }

  if (params.slow_candidates) {
    arr.push('Slow candidates')
  }

  if (modeHasMask(params.attack_mode) && params.mask_increment) {
    if (params.mask_increment_max > 0) {
      arr.push(`Mask increment (min ${params.mask_increment_min}, max ${params.mask_increment_max})`)
    } else {
      arr.push('Mask increment')
    }
  }

  if (props.isDistributed) {
    arr.push('Distributed')
  }

  return arr.join(', ')
})
</script>

<template>
  <table class="compact-table table w-full">
    <thead>
      <tr>
        <th class="w-1/2">Option</th>
        <th class="w-1/2">Value</th>
      </tr>
    </thead>
    <tbody>
      <tr v-if="hashcatParams.wordlist_filenames.length > 0">
        <td><strong>Wordlist</strong></td>
        <td>{{ hashcatParams.wordlist_filenames.map(id => listfileName(id)).join(', ') }}</td>
      </tr>

      <tr v-if="hashcatParams.rules_filenames.length > 0">
        <td><strong>Rules</strong></td>
        <td>{{ hashcatParams.rules_filenames.map(id => listfileName(id)).join(', ') }}</td>
      </tr>

      <tr v-if="hashcatParams.mask != ''">
        <td><strong>Mask</strong></td>
        <td class="font-mono">{{ hashcatParams.mask }}</td>
      </tr>

      <tr v-if="extraOptionsStr != ''">
        <td><strong>Extra Options</strong></td>
        <td>{{ extraOptionsStr }}</td>
      </tr>
    </tbody>
  </table>
</template>
