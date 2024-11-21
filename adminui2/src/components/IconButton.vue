<script setup lang="ts">
const props = defineProps<{
  color: string
  icon: string
  tooltip: string
}>()

const hoverClass = props.color.length > 0 ? 'hover:btn-' + props.color : ''
</script>

<template>
  <div class="tooltip" :data-tip="props.tooltip">
    <button :class="'btn btn-ghost btn-xs ' + hoverClass">
      <font-awesome-icon :icon="icon" />
    </button>
  </div>
</template>
