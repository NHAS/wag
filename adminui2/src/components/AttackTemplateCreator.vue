<script setup lang="ts">
import { computed, ref } from 'vue'
import { useToast } from 'vue-toastification'

import AttackSettings from '@/components/Wizard/AttackSettings.vue'

import { useAttackSettings } from '@/composables/useAttackSettings'
import { useToastError } from '@/composables/useToastError'

import { useAttackTemplatesStore } from '@/stores/attackTemplates'

const toast = useToast()
const { catcher } = useToastError()

const emit = defineEmits(['onCreated'])

const attackTemplatesStore = useAttackTemplatesStore()

const attackTemplateName = ref('')
const isFormLoading = ref(false)

const { attackSettings, asHashcatParams, validationError: attackSettingsValidationError } = useAttackSettings()

const validationError = computed(() => {
  if (attackTemplateName.value.length < 3) {
    return 'Name must be 3 or more characters'
  }

  return attackSettingsValidationError.value
})

async function onCreateAttackTemplate() {
  isFormLoading.value = true
  try {
    const created = await attackTemplatesStore.create({
      name: attackTemplateName.value,
      hashcat_params: asHashcatParams(0)
    })
    toast.success(`Created new attack tempalte ${created.name}`)
    emit('onCreated')
  } catch (e) {
    catcher(e, 'Failed to create attack template')
  } finally {
    isFormLoading.value = false
  }
}
</script>

<template>
  <h3 class="text-lg font-bold mr-12 mb-4">Create Attack Template</h3>

  <div class="form-control">
    <label class="label font-bold"><span class="label-text">Name</span></label>
    <input type="text" class="input input-bordered" v-model="attackTemplateName" placeholder="Big Wordlist Attack" />
  </div>

  <hr class="my-4" />

  <AttackSettings v-model="attackSettings" />

  <hr class="my-4" />
  <div class="tooltip tooltip-left float-right" :data-tip="validationError">
    <button class="btn btn-primary" :disabled="validationError != null || isFormLoading" @click="() => onCreateAttackTemplate()">
      <span class="loading loading-spinner loading-md" v-if="isFormLoading"></span>
      Create
    </button>
  </div>
</template>
