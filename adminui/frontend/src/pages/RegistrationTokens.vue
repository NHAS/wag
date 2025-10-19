<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useToast } from 'vue-toastification'

import PaginationControls from '@/components/PaginationControls.vue'
import ConfirmModal from '@/components/ConfirmModal.vue'
import RegistrationToken from '@/components/RegistrationToken.vue'
import EmptyTable from '@/components/EmptyTable.vue'

import { deleteRegistrationTokens } from '@/api/registration_tokens'

import { usePagination } from '@/composables/usePagination'
import { useToastError } from '@/composables/useToastError'

import { useTokensStore } from '@/stores/registration_tokens'
import { copyToClipboard } from '@/util/clipboard'

import { Icons } from '@/util/icons'

const tokensStore = useTokensStore()
tokensStore.load(true)

const tokens = computed(() => {
  return tokensStore.tokens ?? []
})

const filterText = ref('')

const filteredTokens = computed(() => {
  const arr = tokens.value

  if (filterText.value == '') {
    return arr
  }

  const searchTerm = filterText.value.trim().toLowerCase()

  return arr.filter(x => x.username.toLowerCase().includes(searchTerm) || x.tag.toLocaleLowerCase().includes(searchTerm))
})

const { next: nextPage, prev: prevPage, totalPages, currentItems: currentTokens, activePage } = usePagination(filteredTokens, 20)

const isCreateTokenModalOpen = ref(false)

const toast = useToast()
const { catcher } = useToastError()

const selectedTokens = ref<string[]>([])
const selectAll = ref(false)

async function deleteTokens(tokensToDelete: string[]) {
  if (tokensToDelete.length == 0) {
    return
  }

  try {
    const resp = await deleteRegistrationTokens(tokensToDelete)

    tokensStore.load(true)
    
    selectAll.value = false
    selectedTokens.value = []

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      toast.success('token ' + tokensToDelete.join(', ') + ' deleted!')
    }
  } catch (e) {
    catcher(e, 'failed to delete token: ')
  }
}



watch(selectAll, newValue => {
  if (newValue) {
    // Select all devices
    selectedTokens.value = currentTokens.value.map(t => t.token)
  } else {
    // Deselect all devices
    selectedTokens.value = []
  }
})

watch(selectedTokens, newVal => {
  if (newVal.length == 0) {
    selectAll.value = false
  }
})
</script>

<template>
  <main class="w-full p-4">
    <RegistrationToken v-model:isOpen="isCreateTokenModalOpen" v-on:success="
      () => {
        tokensStore.load(true)
      }
    "></RegistrationToken>

    <h1 class="text-4xl font-bold mb-4">Registration Tokens</h1>
    <p>Create or delete new registration tokens</p>
    <div class="mt-6 flex flex-wrap gap-6">
      <div class="card w-full bg-base-100 shadow-xl min-w-[800px]">
        <div class="card-body">
          <div class="flex flex-row justify-between">
            <span class="flex">
              <div class="tooltip" data-tip="Add rule">
                <button class="btn btn-ghost" @click="() => (isCreateTokenModalOpen = true)">
                  Add Token <font-awesome-icon :icon="Icons.Add" />
                </button>
              </div>
              <div :class="selectedTokens.length > 0 ? 'tooltip' : null" :data-tip="'Delete ' + selectedTokens.length + ' tokens'">
                <ConfirmModal @on-confirm="() => deleteTokens(selectedTokens)">
                  <button class="btn btn-ghost" :disabled="selectedTokens.length == 0">Bulk Delete<font-awesome-icon
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
                <th>Token</th>
                <th>Username</th>
                <th>Tag</th>
                <th>Groups</th>
                <th>Overwrites</th>
                <th>Uses</th>
              </tr>
            </thead>
            <tbody>
              <tr class="hover group" v-for="token in currentTokens" :key="token.token">
                <th>
                  <input type="checkbox" class="checkbox" v-model="selectedTokens" :value="token.token" />
                </th>
                <td class="font-mono">
                  <div class="flex items-center gap-1">

                    <div class="overflow-hidden text-ellipsis whitespace-nowrap flex-1">
                      {{ token.token }}
                    </div>
                    <button @click="copyToClipboard(token.token)">
                      <font-awesome-icon :icon="Icons.Clipboard" class="text-secondary" />
                    </button>
                  </div>

                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ token.username }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ token.tag }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ token.groups?.join(', ') || '-' }}
                  </div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ token.overwrites }}</div>
                </td>
                <td class="font-mono relative">
                  <span class="overflow-hidden text-ellipsis whitespace-nowrap">{{ token.uses }}</span>
                  <ConfirmModal @on-confirm="() => deleteTokens([token.token])">
                    <button
                      class="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                      <font-awesome-icon :icon="Icons.Delete" class="text-error hover:text-error-focus" />
                    </button>
                  </ConfirmModal>
                </td>
              </tr>
            </tbody>
          </table>
          <EmptyTable v-if="tokens.length == 0" text="No registration tokens" />
          <EmptyTable v-if="tokens.length != 0 && tokens.length == 0" text="No matching tokens" />

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
