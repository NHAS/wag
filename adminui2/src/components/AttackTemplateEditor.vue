<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useToast } from 'vue-toastification'

import AttackSettings from '@/components/Wizard/AttackSettings.vue'

import { AttackTemplateType } from '@/api/attackTemplate'

import { useAttackSettings } from '@/composables/useAttackSettings'
import { useToastError } from '@/composables/useToastError'

import { useAttackTemplatesStore } from '@/stores/attackTemplates'

const props = defineProps<{
  idToEdit: string
}>()

const emit = defineEmits(['onSaved'])

const toast = useToast()
const { catcher } = useToastError()

const attackTemplatesStore = useAttackTemplatesStore()

const { attackSettings, asHashcatParams, loadFromHashcatParams, validationError: attackSettingsValidationError } = useAttackSettings()

const editAttackTemplateName = ref('')
const isFormLoading = ref(false)

const attackTemplateToEdit = computed(() => attackTemplatesStore.byId(props.idToEdit))

watch(attackTemplateToEdit, attackTemplate => {
  if (attackTemplate == null || attackTemplate.hashcat_params == null) {
    return
  }
  loadFromHashcatParams(attackTemplate.hashcat_params)
  editAttackTemplateName.value = attackTemplate.name
})

const editAttackTemplateValidationError = computed(() => {
  if (editAttackTemplateName.value.length < 3) {
    return 'Name must be 3 or more characters'
  }

  return attackSettingsValidationError.value
})

async function onSaveAttackTemplate() {
  try {
    isFormLoading.value = true
    await attackTemplatesStore.update(props.idToEdit, {
      name: editAttackTemplateName.value,
      type: AttackTemplateType,
      hashcat_params: asHashcatParams(0)
    })
    toast.success('Saved!')
    emit('onSaved')
  } catch (e) {
    catcher(e, 'Failed to save attack template')
  } finally {
    isFormLoading.value = false
  }
}
</script>

<template>
  <h3 class="text-lg font-bold mr-12 mb-4">Edit Attack Template</h3>

  <div class="form-control">
    <label class="label font-bold"><span class="label-text">Name</span></label>
    <input type="text" class="input input-bordered" v-model="editAttackTemplateName" placeholder="Big Wordlist Attack" />
  </div>

  <hr class="my-4" />

  <AttackSettings v-model="attackSettings" />

  <hr class="my-4" />
  <div class="tooltip tooltip-left float-right" :data-tip="editAttackTemplateValidationError">
    <button
      class="btn btn-primary"
      :disabled="editAttackTemplateValidationError != null || isFormLoading"
      @click="() => onSaveAttackTemplate()"
    >
      <span class="loading loading-spinner loading-md" v-if="isFormLoading"></span>
      Save
    </button>
  </div>
</template>
