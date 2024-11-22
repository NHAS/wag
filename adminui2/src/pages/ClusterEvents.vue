<script setup lang="ts">
import { computed, ref } from 'vue'

import EmptyTable from '@/components/EmptyTable.vue'
import PaginationControls from '@/components/PaginationControls.vue'
import PageLoading from '@/components/PageLoading.vue'

import { getClusterEvents } from '@/api/cluster'

import { usePagination } from '@/composables/usePagination'
import { useApi } from '@/composables/useApi'

import { useInstanceDetailsStore } from '@/stores/serverInfo'

const instanceDetails = useInstanceDetailsStore()
instanceDetails.load(false)

const { data: events, isLoading: isLoadingEvents, silentlyRefresh: refreshEvents } = useApi(() => getClusterEvents())

const isLoading = computed(() => {
  return isLoadingEvents.value
})

const allEvents = computed(() => events.value?.events ?? [])
const {
  next: nextEventsPage,
  prev: prevEventsPage,
  totalPages: totalEventsPages,
  currentItems: currentEvents,
  activePage: activeEventsPage
} = usePagination(allEvents, 20)

const errors = computed(() => events.value?.errors ?? [])
const {
  next: nextErrorsPage,
  prev: prevErrorsPage,
  totalPages: totalErrorsPages,
  currentItems: currentErrors,
  activePage: activeErrorsPage
} = usePagination(errors, 20)
</script>

<template>
  <main class="w-full p-4">
    <PageLoading v-if="isLoading" />

    <div v-else>
      <h1 class="text-4xl font-bold">Events</h1>
      <div class="mt-6 flex w-full gap-4">
        <div class="card w-1/2 bg-base-100 shadow-xl">
          <div class="card-body">
            <h2 class="card-title">General</h2>
            <table class="table table-fixed">
              <tbody>
                <tr class="hover" v-for="line in currentEvents">
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap">
                    {{ line }}
                  </td>
                </tr>
              </tbody>
            </table>
            <EmptyTable v-if="allEvents.length == 0" text="No events yet" />
          </div>
          <div class="mt-2 w-full text-center mb-3">
            <PaginationControls
              @next="() => nextEventsPage()"
              @prev="() => prevEventsPage()"
              :current-page="activeEventsPage"
              :total-pages="totalEventsPages"
            />
          </div>
        </div>
        <div class="card w-1/2 bg-base-100 shadow-xl">
          <div class="card-body">
            <h2 class="card-title">Errors</h2>
            <table class="table table-fixed">
              <tbody>
                <tr class="hover" v-for="line in currentErrors">
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap">
                    {{ line }}
                  </td>
                </tr>
              </tbody>
            </table>
            <EmptyTable v-if="errors.length == 0" text="No errors!" />
          </div>
          <div class="mt-2 w-full text-center mb-3">
            <PaginationControls
              @next="() => nextErrorsPage()"
              @prev="() => prevErrorsPage()"
              :current-page="activeErrorsPage"
              :total-pages="totalErrorsPages"
            />
          </div>
        </div>
      </div>
    </div>
  </main>
</template>

<style scoped>
thead > tr > th {
  background: none !important;
}

.first-col-bold > tr td:first-of-type {
  font-weight: bold;
}
</style>
