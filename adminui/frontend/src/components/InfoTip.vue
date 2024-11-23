<script setup lang="ts">
import { computed } from 'vue'

import { Icons } from '@/util/icons'

export type PlacementT = 'top' | 'bottom' | 'left' | 'right'

const props = defineProps<{
  tooltip: string
  placement?: PlacementT
}>()

const placementClass = computed(() => {
  if (props.placement === 'top') {
    return ''
  }

  return `tooltip-${props.placement}`
})
</script>

<template>
  <span :class="'tooltip font-normal ' + placementClass" :data-tip="props.tooltip">
    <font-awesome-icon :icon="Icons.Info" />
  </span>
</template>
