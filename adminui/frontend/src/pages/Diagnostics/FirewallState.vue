<script setup lang="ts">
import { computed } from 'vue'

import { useApi } from '@/composables/useApi'

import { getFirewallState } from '@/api'

const { data: fwState, isLoading: isLoadingState } = useApi(() => getFirewallState())

const isLoading = computed(() => {
  return isLoadingState.value
})

const state = computed(() => fwState.value ?? {})
</script>

<template>
  <main class="w-full p-4">
    <PageLoading v-if="isLoading" />
    <div v-else>
      <h1 class="text-4xl font-bold mb-4">Wireguard peers</h1>
      <p>Firewall State, all rules and devices directly deserialised.</p>
      <div class="mt-6 flex flex-wrap w-full">
        <div class="card w-full bg-base-100 shadow-xl min-w-[800px]">
          <div class="card-body">
            <pre>{{ state }}</pre>
          </div>
        </div>
      </div>
    </div>
  </main>
</template>

<style scoped>
.hashlist-table.table-sm :where(th, td) {
  padding-top: 0.4rem;
  padding-bottom: 0.4rem;
}
</style>
