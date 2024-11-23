<script setup lang="ts">
import { computed, ref } from 'vue'
import { useToast } from 'vue-toastification'

import { useApi } from '@/composables/useApi'
import { useToastError } from '@/composables/useToastError'

import { checkFirewallRule, getFirewallState, type FirewallTestRequestDTO } from '@/api'

const toast = useToast()
const { catcher } = useToastError()

const result = ref('')
const inputMode = ref({} as FirewallTestRequestDTO)


const isLoadingTest = ref(false)

async function checkRule() {
  try {
    isLoadingTest.value = true
    const resp = await checkFirewallRule(inputMode.value)
    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    }

    result.value = resp.message
  } catch (e) {
    catcher(e, 'failed to check rule: ')
  } finally {
    isLoadingTest.value = false
  }
}
</script>

<template>
  <main class="w-full p-4">
    <h1 class="text-4xl font-bold mb-4">Firewall Decision</h1>
    <p>
      Test the firewall decision for a given user with traffic, this tool will run a test packet through the program and get allow or drop.
    </p>
    <div class="mt-6 flex flex-wrap w-full">
      <div class="card bg-base-100 shadow-xl min-w-[985px] max-w-full">
        <div class="card-body">
          <div class="grid grid-rows-2 grid-col-1 gap-4">
            <div class="row">
              <div class="flex flex-wrap -mx-3 mb-6">
                <div class="px-3">
                  <input v-model=inputMode.address class="input input-bordered w-full" id="device" type="text" placeholder="Device internal IP Address" required />
                </div>
                <div class="px-3">
                  <input v-model=inputMode.target class="input input-bordered w-full" id="target" type="text" placeholder="Target ip address" required />
                </div>
                <div class="px-3">
                  <input v-model=inputMode.port class="input input-bordered w-full" id="port" type="number" placeholder="Port" required />
                </div>
                <div class="px-3">
                  <select v-model=inputMode.protocol class="select select-bordered" name="protocol" required>
                    <option value="udp">UDP</option>
                    <option value="tcp">TCP</option>
                    <option value="icmp">ICMP</option>
                  </select>
                </div>
                <button type="submit" class="btn btn-primary" @click="checkRule()">
                  <span class="loading loading-spinner loading-md" v-if="isLoadingTest"></span>
                  Test
                </button>
              </div>
            </div>
            <div class="row">
              <div class="col">
                <pre>{{ result }}</pre>
              </div>
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
