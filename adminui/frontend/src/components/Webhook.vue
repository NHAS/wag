<script setup lang="ts">
import { computed, ref } from 'vue'
import { useToast } from 'vue-toastification'

import Modal from './Modal.vue'

import { useToastError } from '@/composables/useToastError'
import { WebhookActions,  type WebhookCreateRequestDTO, type WebhookInputDTO } from '@/api'
import EmptyTable from './EmptyTable.vue'



const toast = useToast()
const { catcher } = useToastError()

const props = defineProps<{
  isOpen: boolean
  onSuccess?: (data?: any) => void
}>()


const emit = defineEmits(['update:isOpen'])

const isOpen = computed({
  get: () => props.isOpen,
  set: (value: boolean) => emit('update:isOpen', value)
})

const newWebhook = ref({ action: WebhookActions.CreateRegistrationToken } as WebhookCreateRequestDTO)



const newAttributes: WebhookInputDTO = {
  attributes: [
    { key: "test.test", value: "toast" },
    { key: "test.test", value: "toast" }, { key: "test.test", value: "toast" }, { key: "test.test", value: "toast" }, { key: "test.test", value: "toast" }, { key: "test.test", value: "toast" }, { key: "test.test", value: "toast" }, { key: "test.test", value: "toast" }
  ]
}

</script>

<template>
  <Modal v-model:isOpen="isOpen">
    <div class="w-screen  max-w-[700px]">
      <h3 class="text-lg font-bold pb-2">Create Webhook</h3>
      <p>Send your JSON webhook to the following URL.</p>
      <div class="mt-8">
        <div>
          <label for="username" class="block font-medium text-gray-900">Webhook URL</label>
          <input type="text" id="username" class="input input-bordered input-sm w-full" disabled
            v-model="newWebhook.webhook" />
        </div>


        <div>
          <label for="action" class="block font-medium text-gray-900 pt-6">Action</label>
          <div class="flex gap-6">
            <select class="flex-1 select select-bordered" name="action" v-model="newWebhook.action">
              <option v-for="action in WebhookActions" :selected="action == newWebhook.action" :value="action"
                :key="action">
                {{ action }}
              </option>
            </select>
            <div >
              <p>Creates a registration token on webhook.</p>
              <p>Requires <b>Token</b> and <b>Username attribute roles</b>. </p>
            </div>
          </div>
        </div>


        <div>
          <label class="block font-medium text-gray-900 pt-6 pb-2">Incoming Attributes</label>
          <table class="table w-full">
            <tbody>
              <tr class="hover" v-for="(attribute, index) in newAttributes.attributes" :key="'log-line-' + index">
                <td>
                  {{ attribute.key }}
                </td>
                <td>
                  {{ attribute.value }}
                </td>
              </tr>
            </tbody>
          </table>
          <EmptyTable v-if="newAttributes.attributes.length == 0" text="Waiting for webhook input!"></EmptyTable>

        </div>

        <span class="mt-4 flex">
          <button class="btn btn-primary">Create</button>

          <div class="flex flex-grow"></div>

          <button class="btn btn-secondary" @click="() => (isOpen = false)">Cancel</button>
        </span>
      </div>
    </div>
  </Modal>
</template>
