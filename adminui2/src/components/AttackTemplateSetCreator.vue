<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { computed, ref } from 'vue'
import { useToast } from 'vue-toastification'

import { AttackTemplateType } from '@/api/attackTemplate'

import { useToastError } from '@/composables/useToastError'

import { useAttackTemplatesStore } from '@/stores/attackTemplates'

const attackTemplateStore = useAttackTemplatesStore()
const { templates: allTemplates } = storeToRefs(attackTemplateStore)

const templates = computed(() => allTemplates.value.filter(x => x.type === AttackTemplateType))

const emit = defineEmits(['onCreated'])

const toast = useToast()
const { catcher } = useToastError()

const attackTemplateName = ref('')
const selectedAttackIDs = ref<string[]>([])

const isFormLoading = ref(false)

const validationError = computed(() => {
  if (attackTemplateName.value.length < 3) {
    return 'Name must be 3 or more characters'
  }
  if (selectedAttackIDs.value.length === 0) {
    return 'Select at least one template'
  }
  return null
})

async function onCreate() {
  try {
    isFormLoading.value = true
    await attackTemplateStore.createSet({
      name: attackTemplateName.value,
      attack_template_ids: selectedAttackIDs.value
    })
    toast.success('Created attack template set')
    emit('onCreated')
  } catch (e) {
    catcher(e)
  } finally {
    isFormLoading.value = false
  }
}

function toggleSelected(id: string) {
  if (selectedAttackIDs.value.includes(id)) {
    selectedAttackIDs.value = selectedAttackIDs.value.filter(x => x != id)
  } else {
    selectedAttackIDs.value = [...selectedAttackIDs.value, id]
  }
}
</script>

<template>
  <h3 class="text-lg font-bold mr-12 mb-4">Create Attack Template Set</h3>
  <div class="form-control">
    <label class="label font-bold"><span class="label-text">Name</span></label>
    <input type="text" class="input input-bordered" v-model="attackTemplateName" placeholder="Standard WPA2 Attack Set" />
  </div>

  <hr class="my-4" />

  <label class="label font-bold"><span class="label-text">Select Attack Templates</span></label>
  <table class="compact-table table w-full min-w-[600px]">
    <tbody>
      <tr>
        <td>Select</td>
        <td>Name</td>
      </tr>
      <tr v-for="tmpl in templates" :key="tmpl.id" @click="toggleSelected(tmpl.id)" class="cursor-pointer">
        <td>
          <input
            type="checkbox"
            class="checkbox checkbox-xs align-middle"
            :class="selectedAttackIDs.includes(tmpl.id) ? 'checkbox-primary' : ''"
            :checked="selectedAttackIDs.includes(tmpl.id)"
          />
        </td>
        <td>{{ tmpl.name }}</td>
      </tr>
    </tbody>
  </table>

  <hr class="my-4" />

  <div class="tooltip tooltip-left float-right" :data-tip="validationError">
    <button class="btn btn-primary" :disabled="validationError != null || isFormLoading" @click="() => onCreate()">
      <span class="loading loading-spinner loading-md" v-if="isFormLoading"></span>
      Create
    </button>
  </div>
</template>
