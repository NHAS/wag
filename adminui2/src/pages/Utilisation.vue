<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

import EmptyTable from '@/components/EmptyTable.vue'

import { getJobCountPerUser } from '@/api/groups'

import { useApi } from '@/composables/useApi'

const { data, silentlyRefresh } = useApi(getJobCountPerUser)

let intervalId = ref<number | null>(null)

onMounted(() => {
  intervalId.value = setInterval(() => silentlyRefresh, 30 * 1000)
})

onBeforeUnmount(() => {
  if (intervalId.value != null) {
    clearInterval(intervalId.value)
  }
})

const sortedData = computed(() => data.value?.result.slice().sort((a, b) => b.job_count - a.job_count) ?? [])
</script>

<template>
  <main class="w-full p-4">
    <h1 class="text-4xl font-bold">Utilisation</h1>
    <div class="mt-6 flex flex-wrap gap-6">
      <div class="card min-w-[800px] bg-base-100 shadow-xl">
        <div class="card-body">
          <div class="flex flex-row justify-between">
            <h2 class="card-title">Job Count per User</h2>
          </div>

          <table class="table w-full">
            <thead>
              <tr>
                <th>User</th>
                <th>Job Count</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in sortedData" :key="row.username">
                <td>{{ row.username }}</td>
                <td>{{ row.job_count }}</td>
              </tr>
            </tbody>
          </table>
          <EmptyTable v-if="sortedData.length == 0" text="No Jobs Running" icon="fa-bars-progress" />
        </div>
      </div>
    </div>
  </main>
</template>
