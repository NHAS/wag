<script setup lang="ts">
import { computed, ref } from 'vue'

import PaginationControls from '@/components/PaginationControls.vue'
import PageLoading from '@/components/PageLoading.vue'

import { useApi } from '@/composables/useApi'
import { usePagination } from '@/composables/usePagination'

import { getWireguardPeers } from '@/api'

const { data: wgData, isLoading: isLoadingPeers } = useApi(() => getWireguardPeers())

const isLoading = computed(() => {
  return isLoadingPeers.value
})

const filterText = ref('')

const allPeers = computed(() => wgData.value ?? [])

const filteredPeers = computed(() => {
  const arr = allPeers.value

  if (filterText.value == '') {
    return arr
  }

  const searchTerm = filterText.value.trim().toLowerCase()

  return arr.filter(
    x => x.address.toLowerCase().includes(searchTerm) || x.last_endpoint.includes(searchTerm) || x.public_key.includes(searchTerm)
  )
})

const { next: nextPage, prev: prevPage, totalPages, currentItems: currentPeers, activePage } = usePagination(filteredPeers, 20)
</script>

<template>
  <main class="w-full p-4">
    <PageLoading v-if="isLoading" />
    <div v-else>
      <h1 class="text-4xl font-bold mb-4">Wireguard peers</h1>
      <p>
        Wireguard devices attached to current node (similiar to wg).<br />
        While this page will show all wireguard devices registered to the cluster, it will only show liveness stats for the current node.
      </p>
      <div class="mt-6 flex flex-wrap gap-6">
        <div class="card w-full bg-base-100 shadow-xl min-w-[800px]">
          <div class="card-body">
            <div class="flex flex-row justify-between">
              <div></div>
              <div class="form-control">
                <label class="label">
                  <input type="text" class="input input-bordered input-sm" placeholder="Filter..." v-model="filterText" />
                </label>
              </div>
            </div>

            <table class="table table-fixed w-full">
              <thead>
                <tr>
                  <th>Address</th>
                  <th>Public Key</th>
                  <th>Endpoint Address</th>
                  <th>Recieved Bytes</th>
                  <th>Sent Bytes</th>
                  <th>Last Handshake Time</th>
                </tr>
              </thead>
              <tbody>
                <tr class="hover group" v-for="peer in currentPeers" :key="peer.address">
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ peer.address }}</div>
                  </td>
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ peer.public_key }}</div>
                  </td>
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ peer.last_endpoint }}</div>
                  </td>
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ peer.rx }}</div>
                  </td>
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ peer.tx }}</div>
                  </td>
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ peer.last_handshake_time }}</div>
                  </td>
                </tr>
              </tbody>
            </table>

            <div class="mt-2 w-full text-center">
              <PaginationControls @next="() => nextPage()" @prev="() => prevPage()" :current-page="activePage" :total-pages="totalPages" />
            </div>
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
