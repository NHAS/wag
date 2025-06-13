<script setup lang="ts">
import { computed, ref } from 'vue'
import { useToast } from 'vue-toastification'

import EmptyTable from '@/components/EmptyTable.vue'
import PaginationControls from '@/components/PaginationControls.vue'
import PageLoading from '@/components/PageLoading.vue'
import Modal from '@/components/Modal.vue'

import { acknowledgeClusterError, getClusterEvents } from '@/api/cluster'

import { usePagination } from '@/composables/usePagination'
import { useApi } from '@/composables/useApi'
import { useToastError } from '@/composables/useToastError'

import { useInstanceDetailsStore } from '@/stores/serverInfo'

import { Icons } from '@/util/icons'

import { type AcknowledgeErrorResponseDTO, type EventErrorDTO, type GeneralEvent } from '@/api'

const instanceDetails = useInstanceDetailsStore()
instanceDetails.load(false)

const { data: events, isLoading: isLoadingEvents, silentlyRefresh: refresh } = useApi(() => getClusterEvents())

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

const toast = useToast()
const { catcher } = useToastError()

async function acknowledgeError(error: EventErrorDTO) {
  try {
    const data: AcknowledgeErrorResponseDTO = {
      error_id: error.error_id
    }
    const resp = await acknowledgeClusterError(data)

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      refresh()
      isErrorInspectionModalOpen.value = false
    }
  } catch (e) {
    catcher(e, 'failed to acknowledged error: ')
  }
}

const isErrorInspectionModalOpen = ref(false)
const inspectedError = ref<EventErrorDTO>({} as EventErrorDTO)

function openErrorInspectionModal(error: EventErrorDTO) {
  inspectedError.value = error
  isErrorInspectionModalOpen.value = true
}

const isInspectionModalOpen = ref(false)
const inspectedEvent = ref<GeneralEvent>({ state: { previous: '', current: '' } } as GeneralEvent)
function openEventInspectionModal(error: GeneralEvent) {
  inspectedEvent.value = error
  isInspectionModalOpen.value = true
}
</script>

<template>
  <main class="w-full p-4">
    <Modal v-model:isOpen="isErrorInspectionModalOpen">
      <div class="w-screen max-w-[600px]">
        <h3 class="text-lg font-bold">Error {{ inspectedError.error_id }}</h3>
        <div class="mt-8">
          <p>Error details</p>

          <p>Node: {{ inspectedError.node_id }}</p>
          <p>
            Time:
            {{
              new Date(inspectedError.time).toLocaleString(undefined, {
                weekday: 'short',
                hour: '2-digit',
                minute: '2-digit'
              })
            }}
          </p>

          <label for="members" class="block font-medium text-gray-900 pt-6">Error:</label>
          <textarea class="disabled textarea textarea-bordered w-full font-mono" rows="3" disabled v-model="inspectedError.error"></textarea>

          <label for="members" class="block font-medium text-gray-900 pt-6">Event JSON:</label>
          <textarea
            disabled
            class="disabled textarea textarea-bordered w-full font-mono"
            rows="3"
            v-model="inspectedError.failed_event_data"
          ></textarea>

          <span class="mt-4 flex">
            <button class="btn btn-primary" @click="() => acknowledgeError(inspectedError)">Acknowledge</button>

            <div class="flex flex-grow"></div>

            <button class="btn btn-secondary" @click="() => (isErrorInspectionModalOpen = false)">Cancel</button>
          </span>
        </div>
      </div>
    </Modal>
    <Modal v-model:isOpen="isInspectionModalOpen">
      <div class="w-screen max-w-[600px]">
        <h3 class="text-lg font-bold overflow-hidden text-ellipsis whitespace-nowrap">Event Key: {{ inspectedEvent.key }}</h3>
        <div class="mt-8">
          <p>
            <span class="font-medium text-gray-900 pt-6">Time:</span>
            {{
              new Date(inspectedEvent.time).toLocaleString(undefined, {
                weekday: 'short',
                hour: '2-digit',
                minute: '2-digit'
              })
            }}
          </p>

          <label for="members" class="block font-medium text-gray-900 pt-6">New Key Value JSON:</label>
          <textarea
            class="disabled textarea textarea-bordered w-full font-mono"
            disabled
            rows="3"
            v-model="inspectedEvent.state.current"
          ></textarea>

          <div v-if="inspectedEvent.state.previous.length > 0">
            <label for="members" class="block font-medium text-gray-900 pt-6">Previous Key Value JSON:</label>
            <textarea
              class="disabled textarea textarea-bordered w-full font-mono"
              rows="3"
              disabled
              v-model="inspectedEvent.state.previous"
            ></textarea>
          </div>

          <span class="mt-4 flex">
            <div class="flex flex-grow"></div>
            <button class="btn btn-secondary" @click="() => (isInspectionModalOpen = false)">Close</button>
          </span>
        </div>
      </div>
    </Modal>
    <PageLoading v-if="isLoading" />

    <div v-else>
      <h1 class="text-4xl font-bold">Events</h1>
      <div class="mt-6 flex w-full gap-4">
        <div class="card w-1/2 bg-base-100 shadow-xl">
          <div class="card-body">
            <h2 class="card-title">General</h2>
            <table class="table table-fixed">
              <tbody>
                <tr
                  class="hover group" 
                  v-for="(event, index) in currentEvents"
                  :key="'cluster-events-' + index"
                  v-on:dblclick="openEventInspectionModal(event)"
                >
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap w-[130px]">
                    {{
                      new Date(event.time).toLocaleString(undefined, {
                        weekday: 'short',
                        hour: '2-digit',
                        minute: '2-digit'
                      })
                    }}
                  </td>
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap">
                    <div class="font-medium">{{ event.key }}</div>
                  </td>
                  <td class="relative overflow-hidden text-ellipsis whitespace-nowrap w-[140px]">
                    <div class="font-medium mr-6">{{ event.type }}</div>
                    <button
                      @click="openEventInspectionModal(event)"
                      class="absolute right-9 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity duration-200"
                    >
                      <font-awesome-icon :icon="Icons.Inspect" class="text-secondary hover:text-secondary-focus" />
                    </button>
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
                <tr
                  class="hover group"
                  v-for="error in currentErrors"
                  :key="error.error_id"
                  v-on:dblclick="openErrorInspectionModal(error)"
                >
                  <!-- Time -->
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap w-[120px]">
                    {{
                      new Date(error.time).toLocaleString(undefined, {
                        weekday: 'short',
                        hour: '2-digit',
                        minute: '2-digit'
                      })
                    }}
                  </td>
                  <td class="relative">
                    <div class="font-medium mr-12 overflow-hidden text-ellipsis whitespace-nowrap">{{ error.error }}</div>
                    <button
                      @click="openErrorInspectionModal(error)"
                      class="absolute right-9 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity duration-200"
                    >
                      <font-awesome-icon :icon="Icons.Inspect" class="text-secondary hover:text-secondary-focus" />
                    </button>
                    <button
                      @click="acknowledgeError(error)"
                      class="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity duration-200"
                    >
                      <font-awesome-icon :icon="Icons.Tick" class="text-success hover:text-success-focus" />
                    </button>
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
