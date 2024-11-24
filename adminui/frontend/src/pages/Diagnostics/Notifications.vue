<script setup lang="ts">
import { ref } from 'vue'
import { useToast } from 'vue-toastification'

import { useToastError } from '@/composables/useToastError'

import { testNotifications, type GenericResponseDTO, type TestNotificationsRequestDTO } from '@/api'

const toast = useToast()
const { catcher } = useToastError()

const result = ref({} as GenericResponseDTO)
const inputMode = ref({} as TestNotificationsRequestDTO)

const isLoading = ref(false)

async function sendNotification() {
  try {
    isLoading.value = true
    const resp = await testNotifications(inputMode.value)
    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    }

    result.value = resp
  } catch (e) {
    catcher(e, 'failed to send test notification rule: ')
  } finally {
    isLoading.value = false
  }
}
</script>

<template>
  <main class="w-full p-4">
    <h1 class="text-4xl font-bold mb-4">Send Test Notification</h1>
    <p>Raise a fake error on this cluster node to test alerting.</p>
    <div class="mt-6 flex flex-wrap w-full">
      <div class="card bg-base-100 shadow-xl min-w-[800px] max-w-full">
        <div class="card-body">
          <div class="gap-4">
            <div class="row">
              <div class="col">
                <div class="flex flex-wrap -mx-3 mb-6">
                  <div class="px-3">
                    <input
                      v-model="inputMode.message"
                      class="input input-bordered"
                      id="message"
                      type="text"
                      placeholder="Notification Message"
                      required
                    />
                  </div>
                  <button type="submit" class="btn btn-primary" @click="sendNotification()">
                    <span class="loading loading-spinner loading-md" v-if="isLoading"></span>
                    Send
                  </button>
                </div>
              </div>
            </div>
            <div class="row">
              <div class="col">
                <pre>{{ result.message }}</pre>
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
