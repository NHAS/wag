<script setup lang="ts">
import { ref } from 'vue'
import { useToast } from 'vue-toastification'

import { useToastError } from '@/composables/useToastError'

import { checkFirewallRule, getUserAcls, type AclsTestRequestDTO, type AclsTestResponseDTO } from '@/api'

const toast = useToast()
const { catcher } = useToastError()

const result = ref({} as AclsTestResponseDTO)
const inputMode = ref({} as AclsTestRequestDTO)

const isLoadingAcls = ref(false)

async function loadUserAcls() {
  try {
    isLoadingAcls.value = true
    const resp = await getUserAcls(inputMode.value)
    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    }

    result.value = resp
  } catch (e) {
    catcher(e, 'failed to check rule: ')
  } finally {
    isLoadingAcls.value = false
  }
}
</script>

<template>
  <main class="w-full p-4">
    <h1 class="text-4xl font-bold mb-4">Check ACLs</h1>
    <p>
      Here you can test the wag acl composition engine, submit a username and see what real acls are applied.
    </p>
    <div class="mt-6 flex flex-wrap w-full">
      <div class="card bg-base-100 shadow-xl min-w-[800px] max-w-full">
        <div class="card-body">
          <div class="gap-4">
            <div class="row">
              <div class="col">
              <div class="flex flex-wrap -mx-3 mb-6">
                <div class="px-3">
                  <input
                    v-model="inputMode.username"
                    class="input input-bordered "
                    id="username"
                    type="text"
                    placeholder="Username"
                    required
                  />
                </div>
                <button type="submit" class="btn btn-primary" @click="loadUserAcls()">
                  <span class="loading loading-spinner loading-md" v-if="isLoadingAcls"></span>
                  Fetch
                </button>
              </div>
            </div>
            </div>
            <div class="row">
              <div class="col">
                <pre>{{ result.acls }}</pre>
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
