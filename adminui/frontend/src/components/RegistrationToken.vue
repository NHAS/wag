<script setup lang="ts">
import { computed, ref } from 'vue'
import { useToast } from 'vue-toastification'

import Modal from './Modal.vue'

import { createRegistrationToken } from '@/api/registration_tokens'

import { useToastError } from '@/composables/useToastError'

import type { RegistrationTokenRequestDTO } from '@/api'

const toast = useToast()
const { catcher } = useToastError()

const props = defineProps<{
  isOpen: boolean
  onSuccess?: (data?: any) => void
}>()

const newToken = ref({ uses: 1 } as RegistrationTokenRequestDTO)

const emit = defineEmits(['update:isOpen'])

const isOpen = computed({
  get: () => props.isOpen,
  set: (value: boolean) => emit('update:isOpen', value)
})

async function createToken() {
  if (newToken.value.username == '') {
    toast.error('Empty usernames are not allowed')
    return
  }

  try {
    const resp = await createRegistrationToken(newToken.value)
    emit('update:isOpen', false)

    props.onSuccess?.()

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } 
    
    toast.success('token ' + resp.message + ' for ' + newToken.value.username + ' created!')
    
  } catch (e) {
    catcher(e, 'failed to create token: ')
  } finally {
    newToken.value = { uses: 1 } as RegistrationTokenRequestDTO
  }
}
</script>

<template>
  <Modal v-model:isOpen="isOpen">
    <div class="w-screen max-w-[600px]">
      <h3 class="text-lg font-bold">Create Registration Token</h3>
      <div class="mt-8">
        <div class="form-group">
          <label for="username" class="block font-medium text-gray-900">Username</label>
          <input type="text" id="username" class="input input-bordered input-sm w-full" required v-model="newToken.username" />
        </div>

        <div class="form-group">
          <label for="token" class="block font-medium text-gray-900 pt-6">Token</label>
          <input type="text" id="token" class="input input-bordered input-sm w-full" v-model="newToken.token" placeholder="(Optional)" />
        </div>

        <div class="form-group">
          <label for="overwrites" class="block font-medium text-gray-900 pt-6">Overwrites</label>
          <input
            type="text"
            id="overwrites"
            class="input input-bordered input-sm w-full"
            v-model="newToken.overwrites"
            placeholder="(Optional)"
          />
        </div>

        <div class="form-group">
          <label for="groups" class="block font-medium text-gray-900 pt-6">Groups</label>
          <input type="text" id="groups" class="input input-bordered input-sm w-full" v-model="newToken.groups" placeholder="(Optional)" />
        </div>

        <div class="form-group">
          <label for="uses" class="block font-medium text-gray-900 pt-6">Uses</label>
          <input type="number" id="uses" class="input input-bordered input-sm w-full" v-model="newToken.uses" />
        </div>

        <span class="mt-4 flex">
          <button class="btn btn-primary" @click="() => createToken()">Create</button>

          <div class="flex flex-grow"></div>

          <button class="btn btn-secondary" @click="() => (isOpen = false)">Cancel</button>
        </span>
      </div>
    </div>
  </Modal>
</template>
