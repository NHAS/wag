<script setup lang="ts">
import { computed, ref } from 'vue'
import { useToast } from 'vue-toastification'

import Modal from './Modal.vue'

import { useToastError } from '@/composables/useToastError'
import { WebhookActions, type WebhookCreateRequestDTO, type WebhookInputDTO } from '@/api'
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


const actionOptions = [
  {
    name: "Create Token",
    action: WebhookActions.CreateRegistrationToken,
    requirements: ["Username"],
    optional: ["Tag", "Token"],
    description: "Creates a registration token on webhook."
  },
  {
    name: "Delete Device",
    action: WebhookActions.DeleteDevice,
    requirements: [],
    optional: ["IP", "Tag"],
    description: "Deletes a wireguard peer."
  },
  {

    name: "Delete User",
    action: WebhookActions.DeleteUser,
    requirements: ["Username"],
    optional: [],
    description: "Deletes a user and all associated devices."
  }
]

const selectedAction = computed(() => {
  return actionOptions.find(a => a.action == newWebhook.value.action)
})

const newAttributes: WebhookInputDTO = {
  attributes: [
    { key: "test.test", value: "toast" },
    { key: "test.test", value: "toast" }, { key: "test.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.testtest.test", value: "toast" }, { key: "test.test", value: "toast" }, { key: "test.test", value: "toast" }, { key: "test.test", value: "toast" }, { key: "test.test", value: "toast" }, { key: "test.test", value: "toast" }
  ],
  error: "",
}

</script>

<template>
  <Modal v-model:isOpen="isOpen">
    <div class="w-screen  max-w-[700px]">
      <h3 class="text-lg font-bold pb-2">Create Webhook</h3>
      <p>Send your JSON webhook to the following URL.</p>
      <div class="mt-8">
        <div>
          <label for="webhookURL" class="block font-medium  pb-4">Webhook URL</label>
          <input type="text" id="webhookURL" class="input input-bordered input-sm w-full" disabled
            v-model="newWebhook.webhook" />
        </div>


        <div>
          <label for="action" class="block font-medium  pt-6 pb-4">Action</label>
          <div class="grid grid-cols-2 grid-rows-1 gap-6 min-h-[73px]">

            <select class="select select-bordered" name="action" v-model="newWebhook.action">
              <option v-for="option in actionOptions" :selected="option.action == newWebhook.action"
                :value="option.action" :key="option.action">
                {{ option.name }}
              </option>
            </select>


            <div>
              <p>{{ selectedAction?.description }}</p>
              <p>Requires {{ }}<b>Token</b> and <b>Username</b> attribute roles.</p>
              <p>Optional <b>test</b></p>
            </div>

          </div>
        </div>


        <div>
          <label class="block font-medium  pt-6 pb-2">Incoming</label>
          <div v-if="newAttributes.error == ''" class='overflow-y-scroll max-h-[230px]'>
            <table class="table overflow-scroll">
              <thead>
                <td>Attribute</td>
                <td>Value</td>
              </thead>
              <tbody>
                <tr class="hover" v-for="(attribute, index) in newAttributes.attributes" :key="attribute.key">
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap max-w-[200px] min-w-[200px]">
                    {{ attribute.key }}
                  </td>
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap max-w-[100px] min-w-[100px]">
                    {{ attribute.value }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <EmptyTable v-if="newAttributes.attributes.length == 0 || newAttributes.error != ''"
            :text="newAttributes.error == '' ? 'Waiting for webhook input!' : newAttributes.error"></EmptyTable>

        </div>

        <div>
          <label class="block font-medium  pt-6 pb-6">Selection</label>
          <div class="flex gap-4">
            <label for="webhookURL" class="font-small pb-4 min-w-[75px]">Username</label>
            <input type="text" id="webhookURL" class="input input-bordered input-sm w-full"
             placeholder="Attribute" />
          </div>


          <div class="flex gap-4">
            <label for="webhookURL" class="font-small  pb-4 min-w-[75px]" >Token</label>
            <input type="text" id="webhookURL" class="input input-bordered input-sm w-full"  placeholder="(Optional)"/>
          </div>
          <div class="flex gap-4">
            <label for="webhookURL" class="font-small  pb-4 min-w-[75px]" >Tag</label>
            <input type="text" id="webhookURL" class="input input-bordered input-sm w-full"
             placeholder="(Optional)" />
          </div>
        </div>

        <span class="mt-4 flex pt-6">
          <button class="btn btn-primary">Create</button>

          <div class="flex flex-grow"></div>

          <button class="btn btn-secondary" @click="() => (isOpen = false)">Cancel</button>
        </span>
      </div>
    </div>
  </Modal>
</template>
