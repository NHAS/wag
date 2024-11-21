<script setup lang="ts">
import { ref } from 'vue'
import { storeToRefs } from 'pinia'

import HashesInput from '@/components/RulesInput.vue'

import { searchPotfile } from '@/api/potfile'
import type { PotfileSearchResponseDTO } from '@/api/types'

import { useHashesInput } from '@/composables/useHashesInput'
import { useToastError } from '@/composables/useToastError'

import { useTokensStore } from '@/stores/registration_tokens'

import decodeHex from '@/util/decodeHex'

const { hashesInput, hashesArr } = useHashesInput()

const { catcher } = useToastError()

const isLoading = ref(false)
const results = ref<PotfileSearchResponseDTO | null>(null)

async function doSearch() {
  results.value = null
  isLoading.value = true

  try {
    const response = await searchPotfile(hashesArr.value)
    results.value = response
  } catch (e: any) {
    catcher(e)
  } finally {
    isLoading.value = false
  }
}

const resourcesStore = useTokensStore()

const { getHashTypeName } = storeToRefs(resourcesStore)
resourcesStore.loadHashTypes()
</script>

<template>
  <main class="w-full p-4">
    <h1 class="text-4xl font-bold">Hash Search</h1>
    <small class="mb-2 mt-1 pl-0.5 text-sm">Hint: when you create a hashlist, all hashes are searched automatically for you</small>
    <div class="mt-3 flex flex-wrap gap-6">
      <div class="card bg-base-100 shadow-xl">
        <div class="card-body flex-row gap-3">
          <div class="min-w-[400px]">
            <h2 class="mb-2 text-xl font-semibold">Enter hashes to search (one per-line)</h2>
            <HashesInput v-model="hashesInput" />
            <button class="btn btn-primary mt-2 w-full" :disabled="isLoading" @click="doSearch">
              <span v-if="isLoading" class="loading loading-spinner loading-lg"></span>
              Search
            </button>
          </div>

          <div class="divider divider-horizontal" v-if="results != null"></div>

          <div class="min-w-[600px]" v-if="results != null">
            <h2 class="card-title">Results</h2>
            <table class="compact-table table table-sm w-full">
              <thead>
                <tr>
                  <th>Original Hash</th>
                  <th>Hash Type</th>
                  <th>Cracked Plaintext</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(result, i) in results.results" :key="[i, result.hash, result.hash_type, result.plaintext_hex].join('|')">
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap font-mono" style="max-width: 500px">
                    {{ result.hash }}
                  </td>
                  <td v-if="result.found">{{ getHashTypeName(result.hash_type) }} - {{ result.hash_type }}</td>
                  <td v-else>Unknown</td>
                  <td class="font-mono">
                    <strong>{{ decodeHex(result.plaintext_hex) || '-' }}</strong>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </main>
</template>
