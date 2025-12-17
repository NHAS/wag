<script setup lang="ts">
import { computed, ref, watch, type Ref } from 'vue'
import { useToast } from 'vue-toastification'

import Modal from './Modal.vue'
import EmptyTable from './EmptyTable.vue'

import { useToastError } from '@/composables/useToastError'

import { Icons } from '@/util/icons'
import { copyToClipboard } from '@/util/clipboard'

import {
  createWebhook,
  WebhookActions,
  WebhookInputTypes,
  type WebhookRoles,
  type WebhookAttribute,
  type WebhookCreateRequestDTO,
  type WebhookInputAttributesDTO,
  type WebhookInputType,
  type WebhookTempCreateResponseDTO,
  type WebhookJsonAttributesRoles
} from '@/api'

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
const tempWebhookDetails = ref({} as WebhookTempCreateResponseDTO)

interface attributeType {
  friendlyName: string
  data: Ref<WebhookAttribute | null>
  role: WebhookRoles
}

interface actionOption {
  name: string
  action: WebhookActions
  required: attributeType[]
  optional: attributeType[]

  description: string
}

function attribute(name: string, role: WebhookRoles, defaultVal: WebhookAttribute | null = null): attributeType {
  return { friendlyName: name, role: role, data: ref(defaultVal) }
}

const actionOptions: actionOption[] = [
  {
    name: 'Create Token',
    action: WebhookActions.CreateRegistrationToken,
    required: [attribute('Username', 'as_username'), attribute('Token', 'as_registration_token')],
    optional: [attribute('Tag', 'as_device_tag')],
    description: 'Creates a registration token on webhook.'
  },
  {
    name: 'Delete Device',
    action: WebhookActions.DeleteDevice,
    required: [],
    optional: [attribute('IP', 'as_device_ip'), attribute('Tag', 'as_device_tag')],
    description: 'Deletes a wireguard peer.'
  },
  {
    name: 'Delete User',
    action: WebhookActions.DeleteUser,
    required: [attribute('Username', 'as_username')],
    optional: [],
    description: 'Deletes a user and all associated devices.'
  }
]

const selectedAction = computed(() => {
  const result = actionOptions.find(a => a.action == newWebhook.value.action)
  if (result == undefined || result == null) {
    return actionOptions[0]
  }

  return result
})

const incommingAttributes = ref({
  attributes: [] as WebhookAttribute[],
  error: 'Waiting for webhook input!'
})

const filterText = ref('')

const filteredAttributes = computed(() => {
  const arr = incommingAttributes.value.attributes != null ? incommingAttributes.value.attributes : []

  if (filterText.value == '') {
    return arr
  }

  const searchTerm = filterText.value.trim().toLowerCase()

  return arr.filter(x => x.key.toLowerCase().includes(searchTerm) || x.value?.includes(searchTerm))
})

function requirementsMet(selected: actionOption) {
  // As long as all requirements have been met (not null)
  // and at least one requirement or one optional is set
  return (
    !selected.required.some(s => s.data.value == null) &&
    (selected.required.some(s => s.data.value != null) || selected.optional.some(s => s.data.value != null))
  )
}

let ws: WebSocket | null = null
let pingTimer: number | undefined = undefined

function connectWebSocket() {
  if (ws?.readyState === WebSocket.OPEN) {
    return // Already connected
  }

  try {
    // Replace with your actual WebSocket URL

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${wsProtocol}//${window.location.host}/api/management/webhooks/ws`

    ws = new WebSocket(wsUrl)

    ws.onopen = () => {
      console.log('WebSocket connected')
      pingTimer = setInterval(() => {
        if (ws != null) {
          ws.send(JSON.stringify({ data: 'ping' }))
        }
      }, 10000)
    }

    ws.onmessage = event => {
      try {
        const data = JSON.parse(event.data)
        handleWebSocketMessage(data)
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error)
        toast.error('Failed to parse incoming message')
      }
    }

    ws.onerror = error => {
      console.error('WebSocket error:', error)
      toast.error('Cannot connect to wag server')
    }

    ws.onclose = () => {
      console.log('WebSocket disconnected')
    }
  } catch (error) {
    console.error('Failed to connect WebSocket:', error)
    toast.error('Failed to connect to WebSocket')
  }
}

function handleWebSocketMessage(data: WebhookInputType) {
  switch (data.type) {
    case WebhookInputTypes.AttributeInput: {
      const attributes = data as WebhookInputAttributesDTO

      // Subsequent messages contain incoming attributes
      incommingAttributes.value = {
        attributes: attributes.attributes != null ? attributes.attributes : [],
        error: attributes.error != null ? attributes.error : ''
      }

      break
    }
    case WebhookInputTypes.URL: {
      const inputUrl = data as WebhookTempCreateResponseDTO
      // First message should contain the webhook URL
      newWebhook.value.id = inputUrl.id
      newWebhook.value.auth_header = inputUrl.auth_header
      tempWebhookDetails.value = inputUrl

      console.log(inputUrl)

      incommingAttributes.value.error = 'Waiting for webhook input!'
      break
    }
    default: {
      console.log('Unknown data type: ', data.type)
    }
  }
}

function disconnectWebSocket() {
  if (ws !== null) {
    clearInterval(pingTimer)

    ws.close()
    ws = null
  }
}

function resetState() {
  newWebhook.value = { action: WebhookActions.CreateRegistrationToken } as WebhookCreateRequestDTO
  incommingAttributes.value = {
    attributes: [],
    error: 'Waiting for webhook input!'
  }
  tempWebhookDetails.value = {} as WebhookTempCreateResponseDTO
  filterText.value = ''

  // Reset all attribute selections
  actionOptions.forEach(action => {
    ;[...action.required, ...action.optional].forEach(attr => {
      attr.data.value = null
    })
  })
}

watch(
  isOpen,
  newValue => {
    if (newValue) {
      resetState()
      connectWebSocket()
    } else {
      disconnectWebSocket()
    }
  },
  { immediate: true }
)

async function createWebhookTrigger() {
  try {
    newWebhook.value.json_attribute_roles = {} as WebhookJsonAttributesRoles
    ;[...selectedAction.value.required, ...selectedAction.value.optional].forEach(attr => {
      if (attr.data.value != null) {
        newWebhook.value.json_attribute_roles[attr.role] = attr.data.value.key
      }
    })

    const resp = await createWebhook(newWebhook.value)

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    }

    toast.success('Webhook created!')
    isOpen.value = false

    if (props.onSuccess !== undefined) {
      props.onSuccess()
    }
  } catch (e) {
    catcher(e, 'failed to create webhook: ')
  }
}
</script>

<style src="vue-multiselect/dist/vue-multiselect.min.css"></style>

<template>
  <Modal v-model:isOpen="isOpen">
    <div class="w-screen max-w-[700px]">
      <h3 class="text-lg font-bold pb-2">Create Webhook</h3>
      <p>Send your JSON webhook to the following URL.</p>
      <div class="mt-8">
        <div>
          <label for="webhookURL" class="block font-medium pb-4"
            >Webhook URL<span v-if="tempWebhookDetails.url == ''" class="ml-4 loading loading-spinner loading-xs"></span
          ></label>
          <input type="text" id="webhookURL" class="input input-bordered input-sm w-full" disabled :value="tempWebhookDetails.url" />

          <div class="pt-4">
            <p class="pb-2">The following authentication header will only be displayed here:</p>
            <p class="inline">
              X-AUTH-HEADER: {{ tempWebhookDetails.auth_header == undefined ? 'waiting....' : tempWebhookDetails.auth_header }}
            </p>
            <button
              v-if="tempWebhookDetails.auth_header != undefined"
              class="inline pl-4"
              @click="copyToClipboard('X-AUTH-HEADER: ' + tempWebhookDetails.auth_header)"
            >
              <font-awesome-icon :icon="Icons.Clipboard" class="text-secondary" />
            </button>
          </div>
        </div>

        <div>
          <label for="action" class="block font-medium pt-6 pb-4">Action</label>
          <div class="grid grid-cols-2 grid-rows-1 gap-6 min-h-[73px]">
            <select class="select select-bordered" name="action" v-model="newWebhook.action">
              <option
                v-for="option in actionOptions"
                :selected="option.action == newWebhook.action"
                :value="option.action"
                :key="option.action"
              >
                {{ option.name }}
              </option>
            </select>

            <div>
              <p>{{ selectedAction.description }}</p>
              <p v-if="selectedAction.required.length > 0">
                Requires
                <template v-for="(attr, index) in selectedAction.required" :key="attr">
                  <b>{{ attr.friendlyName }} {{ attr.data.value != null ? '✅' : '' }}</b>
                  <span v-if="index < selectedAction?.required.length - 1"> and </span>
                </template>
                attribute role{{ selectedAction.required.length > 1 ? 's' : '' }}.
              </p>
              <p v-if="selectedAction.optional.length > 0">
                Optional
                <template v-for="(attr, index) in selectedAction.optional" :key="attr">
                  <b>{{ attr.friendlyName }} {{ attr.data.value != null ? '✅' : '' }}</b>
                  <span v-if="index < selectedAction?.optional.length - 1">, </span>
                </template>
              </p>
            </div>
          </div>
        </div>

        <div class="max-h-[230px] min-h-[230px]">
          <div class="flex pt-6 pb-2">
            <label class="block font-medium pt-2">Received</label>
            <div class="flex flex-grow"></div>
            <label class="label">
              <input type="text" class="input input-bordered input-sm" placeholder="Filter..." v-model="filterText" />
            </label>
          </div>
          <div v-if="incommingAttributes.error == ''" class="overflow-y-scroll max-h-[130px]">
            <table class="table overflow-scroll">
              <thead>
                <td>Attribute</td>
                <td>Value</td>
              </thead>
              <tbody>
                <tr class="hover" v-for="attribute in filteredAttributes" :key="attribute.key">
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
          <EmptyTable
            v-if="filteredAttributes.length == 0 || incommingAttributes.error != ''"
            :text="
              incommingAttributes.error == ''
                ? incommingAttributes.attributes.length > 0
                  ? 'Filter doesnt match any attribute'
                  : 'Waiting for webhook input!'
                : incommingAttributes.error
            "
          >
          </EmptyTable>
        </div>

        <div class="min-h-[300px]">
          <label class="block font-medium pb-4 pt-4">Select Attribute</label>

          <template v-for="attribute in selectedAction.required" v-bind:key="attribute.friendlyName">
            <div>
              <label class="typo__label">{{ attribute.friendlyName }}</label>

              <Multiselect
                v-model="attribute.data.value"
                :options="incommingAttributes.attributes"
                :taggable="true"
                @tag="
                  (value: any) => {
                    attribute.data.value = { key: value, value: '' }
                  }
                "
                placeholder="Required"
                label="key"
                track-by="key"
              >
              </Multiselect>
            </div>
          </template>

          <template v-for="attribute in selectedAction.optional" v-bind:key="attribute.friendlyName">
            <div class="gap-4 pt-4">
              <label class="typo__label">{{ attribute.friendlyName }}</label>
              <Multiselect
                v-model="attribute.data.value"
                :options="incommingAttributes.attributes"
                :taggable="true"
                @tag="
                  (value: any) => {
                    attribute.data.value = { key: value, value: '' }
                  }
                "
                placeholder="Optional"
                :allowEmpty="true"
                label="key"
                track-by="key"
              >
              </Multiselect>
            </div>
          </template>
        </div>

        <span class="mt-4 flex pt-6">
          <button class="btn btn-primary" :disabled="!requirementsMet(selectedAction)" @click="createWebhookTrigger">Create</button>

          <div class="flex flex-grow"></div>

          <button class="btn btn-secondary" @click="() => (isOpen = false)">Cancel</button>
        </span>
      </div>
    </div>
  </Modal>
</template>
