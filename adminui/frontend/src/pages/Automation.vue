<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useToast } from 'vue-toastification'

import PaginationControls from '@/components/PaginationControls.vue'
import ConfirmModal from '@/components/ConfirmModal.vue'
import EmptyTable from '@/components/EmptyTable.vue'

import { usePagination } from '@/composables/usePagination'
import { useToastError } from '@/composables/useToastError'

import { copyToClipboard } from '@/util/clipboard'

import { Icons } from '@/util/icons'
import Webhook from '@/components/Webhook.vue'
import { useWebhooksStore } from '@/stores/automation'
import { deleteWebhooks } from '@/api'

const hooksStore = useWebhooksStore()
hooksStore.load(true)

const hooks = computed(() => {
  return hooksStore.hooks ?? []
})

const filterText = ref('')

const filteredWebhookss = computed(() => {
  const arr = hooks.value

  if (filterText.value == '') {
    return arr
  }

  const searchTerm = filterText.value.trim().toLowerCase()

  return arr.filter(x => x.id.toLowerCase().includes(searchTerm))
})

const { next: nextPage, prev: prevPage, totalPages, currentItems: currentHooks, activePage } = usePagination(filteredWebhookss, 20)

const isWebhookModalOpen = ref(false)

const toast = useToast()
const { catcher } = useToastError()

async function deleteHooks(hooksToDelete: string[]) {
  if (hooksToDelete.length == 0) {
    return
  }

  try {
    const resp = await deleteWebhooks(hooksToDelete)

    selectAll.value = false
    selectedHooks.value = []


    hooksStore.load(true)



    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      toast.success('webhook ' + hooksToDelete.join(', ') + ' deleted!')
    }
  } catch (e) {
    catcher(e, 'failed to delete webhook: ')
  }
}

const selectedHooks = ref<string[]>([])
const selectAll = ref(false)

watch(selectAll, newValue => {
  if (newValue) {
    // Select all webhooks
    selectedHooks.value = currentHooks.value.map(t => t.id)
  } else {
    // Deselect all devices
    selectedHooks.value = []
  }
})

watch(selectedHooks, newVal => {
  if (newVal.length == 0) {
    selectAll.value = false
  }
})
</script>

<template>



  <main class="w-full p-4">
    <Webhook v-model:isOpen="isWebhookModalOpen" v-on:success="
      () => {
        hooksStore.load(true)
      }
    "></Webhook>
    <h1 class="text-4xl font-bold mb-4">Automation</h1>
    <p>Ingest webhooks to automatically create registration tokens, delete users or devices.</p>
    <div class="mt-6 flex flex-wrap gap-6">
      <div class="card w-full bg-base-100 shadow-xl min-w-[800px]">
        <div class="card-body">
          <div class="flex flex-row justify-between">
            <span class="flex">
              <div class="tooltip" data-tip="Add rule">
                <button class="btn btn-ghost" @click="() => (isWebhookModalOpen = true)">
                  Add Webhook <font-awesome-icon :icon="Icons.Add" />
                </button>
              </div>
              <div :class="selectedHooks.length > 0 ? 'tooltip' : null" :data-tip="'Delete ' + selectedHooks.length + ' tokens'">
                <ConfirmModal @on-confirm="() => deleteHooks(selectedHooks)">
                  <button class="btn btn-ghost disabled:bg-white" :disabled="selectedHooks.length == 0">Bulk Delete<font-awesome-icon
                      :icon="Icons.Delete"/></button>
                </ConfirmModal>
              </div>
            </span>
            <div class="form-control">
              <label class="label">
                <input type="text" class="input input-bordered input-sm" placeholder="Filter..." v-model="filterText" />
              </label>
            </div>
          </div>

          <table class="table table-fixed w-full">
            <thead>
              <tr>
                <th class="w-10">
                  <input type="checkbox" class="checkbox" v-model="selectAll" />
                </th>
                <th>Webhook</th>
                <th>Action</th>
                <th>Attributes</th>
                <th>Last Use</th>
              </tr>
            </thead>
            <tbody>
              <tr class="hover group" v-for="hook in currentHooks" :key="hook.id">
                <th>
                  <input type="checkbox" class="checkbox" v-model="selectedHooks" :value="hook.id" />
                </th>
                <td class="font-mono">
                  <div class="flex items-center gap-1">

                    <div class="overflow-hidden text-ellipsis whitespace-nowrap flex-1">
                      {{ hook.id }}
                    </div>
                    <button @click="copyToClipboard(hook.id)">
                      <font-awesome-icon :icon="Icons.Clipboard" class="text-secondary" />
                    </button>
                  </div>

                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ hook.action }}</div>
                </td>
                <td class="font-mono flex flex-col">
                        
                  <template v-for="(attribute, index) in hook.json_attribute_roles" :key="attribute" >
                    <div v-if="attribute != ''"class="mt-2 badge badge-secondary text-white font-mono overflow-hidden text-ellipsis whitespace-nowrap">{{ index.replace("as_", "") + ": " + attribute }}</div>
                  </template>
                </td>
                <td class="font-mono relative">
                  <ConfirmModal @on-confirm="() => deleteHooks([hook.id])">
                    <button
                      class="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                      <font-awesome-icon :icon="Icons.Delete" class="text-error hover:text-error-focus" />
                    </button>
                  </ConfirmModal>
                </td>
              </tr>
            </tbody>
          </table>
          <EmptyTable v-if="hooks.length == 0" text="No webhooks defined" />
          <EmptyTable v-if="hooks.length != 0 && hooks.length == 0" text="No matching webhooks" />

          <div class="mt-2 w-full text-center">
            <PaginationControls @next="() => nextPage()" @prev="() => prevPage()" :current-page="activePage"
              :total-pages="totalPages" />
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
