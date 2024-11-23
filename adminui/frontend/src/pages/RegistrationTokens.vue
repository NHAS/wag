<script setup lang="ts">
import { computed, ref } from 'vue'
import { useToast } from 'vue-toastification'

import PaginationControls from '@/components/PaginationControls.vue'
import ConfirmModal from '@/components/ConfirmModal.vue'
import RegistrationToken from '@/components/RegistrationToken.vue'

import { deleteRegistrationTokens } from '@/api/registration_tokens'

import { usePagination } from '@/composables/usePagination'
import { useToastError } from '@/composables/useToastError'

import { useTokensStore } from '@/stores/registration_tokens'

import { Icons } from '@/util/icons'

import type { RegistrationTokenRequestDTO } from '@/api'

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

  return arr.filter(x => x.username.toLowerCase().includes(searchTerm))
})

const { next: nextPage, prev: prevPage, totalPages, currentItems: currentTokens, activePage } = usePagination(filteredTokens, 20)

const isCreateTokenModalOpen = ref(false)

const toast = useToast()
const { catcher } = useToastError()

async function deleteToken(token: RegistrationTokenRequestDTO) {
  //TODO handle multiple
  const tokensToDelete = [token.token]
  try {
    const resp = await deleteRegistrationTokens(tokensToDelete)

    tokensStore.load(true)
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
</script>

<template>
  <main class="w-full p-4">
    <RegistrationToken
      v-model:isOpen="isCreateTokenModalOpen"
      v-on:success="
        () => {
          tokensStore.load(true)
        }
      "
    ></RegistrationToken>

    <h1 class="text-4xl font-bold mb-4">Registration Tokens</h1>
    <p>Create or delete new registration tokens</p>
    <div class="mt-6 flex flex-wrap gap-6">
      <div class="card w-full bg-base-100 shadow-xl min-w-[800px]">
        <div class="card-body">
          <div class="flex flex-row justify-between">
            <div class="tooltip" data-tip="Add rule">
              <button class="btn btn-ghost btn-primary" @click="() => (isCreateTokenModalOpen = true)">
                Add Token <font-awesome-icon :icon="Icons.Add" />
              </button>
            </div>
            <div class="form-control">
              <label class="label">
                <input type="text" class="input input-bordered input-sm" placeholder="Filter..." v-model="filterText" />
              </label>
            </div>
          </div>

          <table class="table table-fixed w-full">
            <thead>
              <tr>
                <th>Token</th>
                <th>Username</th>
                <th>Groups</th>
                <th>Overwrites</th>
                <th>Uses</th>
              </tr>
            </thead>
            <tbody>
              <tr class="hover group" v-for="token in currentTokens" :key="token.token">
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ token.token }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ token.username }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ token.groups?.join(', ') || '-' }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ token.overwrites }}</div>
                </td>
                <td class="font-mono relative">
                  <span class="overflow-hidden text-ellipsis whitespace-nowrap">{{ token.uses }}</span>
                  <ConfirmModal @on-confirm="() => deleteToken(token)">
                    <button
                      class="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity duration-200"
                    >
                      <font-awesome-icon :icon="Icons.Delete" class="text-error hover:text-error-focus" />
                    </button>
                  </ConfirmModal>
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
  </main>
</template>

<style scoped>
.hashlist-table.table-sm :where(th, td) {
  padding-top: 0.4rem;
  padding-bottom: 0.4rem;
}
</style>
