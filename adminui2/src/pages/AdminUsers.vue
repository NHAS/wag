<script setup lang="ts">
import { computed, ref } from 'vue'
import PaginationControls from '@/components/PaginationControls.vue'
import PageLoading from '@/components/PageLoading.vue'

import { useApi } from '@/composables/useApi'
import { usePagination } from '@/composables/usePagination'

import { getAdminUsers } from '@/api'

const { data: adminUsersData, isLoading: isLoadingAdmins } = useApi(() => getAdminUsers())

const isLoading = computed(() => {
  return isLoadingAdmins.value
})

const filterText = ref('')

const allAdmins = computed(() => adminUsersData.value ?? [])

const filteredAdmins = computed(() => {
  const arr = allAdmins.value

  if (filterText.value == '') {
    return arr
  }

  const searchTerm = filterText.value.trim().toLowerCase()

  return arr.filter(x => x.username.toLowerCase().includes(searchTerm) || x.user_type?.includes(searchTerm) || x.ip?.includes(searchTerm))
})

const { next: nextPage, prev: prevPage, totalPages, currentItems: currentAdmins, activePage } = usePagination(filteredAdmins, 20)

</script>

<template>
  <main class="w-full p-4">
    <PageLoading v-if="isLoading" />
    <div v-else>
      <h1 class="text-4xl font-bold">Administrative Users</h1>
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
                  <th>Username</th>
                  <th>Date Added</th>
                  <th>Last Login</th>
                  <th>IP</th>
                  <th>Login Attempts (>5 locked)</th>
                  <th>Temp Password</th>
                </tr>
              </thead>
              <tbody>
                <tr class="hover group" v-for="admin in currentAdmins">
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ admin.username }}</div>
                  </td>
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ admin.date_added }}</div>
                  </td>
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ admin.last_login }}</div>
                  </td>
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ admin.ip }}</div>
                  </td>
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ admin.attempts }}</div>
                  </td>
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ admin.change }}</div>
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
