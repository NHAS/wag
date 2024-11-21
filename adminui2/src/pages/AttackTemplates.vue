<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { ref } from 'vue'
import { useToast } from 'vue-toastification'

import AttackTemplateCreator from '@/components/AttackTemplateCreator.vue'
import AttackTemplateEditor from '@/components/AttackTemplateEditor.vue'
import AttackTemplateSetEditor from '@/components/AttackTemplateSetEditor.vue'
import Modal from '@/components/Modal.vue'
import IconButton from '@/components/IconButton.vue'
import EmptyTable from '@/components/EmptyTable.vue'
import ConfirmModal from '@/components/ConfirmModal.vue'
import PageLoading from '@/components/PageLoading.vue'
import AttackTemplateSetCreator from '@/components/AttackTemplateSetCreator.vue'

import { AttackTemplateSetType, AttackTemplateType } from '@/api/attackTemplate'

import { useToastError } from '@/composables/useToastError'

import { useAttackTemplatesStore } from '@/stores/attackTemplates'

import { Icons } from '@/util/icons'

const attackTemplatesStore = useAttackTemplatesStore()
const { templates, isFirstLoading } = storeToRefs(attackTemplatesStore)
attackTemplatesStore.load(true)

const isCreateModalOpen = ref(false)
const isCreateSetModalOpen = ref(false)
const isEditModalOpen = ref(false)
const isEditSetModalOpen = ref(false)

const attackTemplateToEditId = ref('')
const attackTemplateSetToEditId = ref('')

const toast = useToast()
const { catcher } = useToastError()

async function onOpenEditAttackSettings(id: string) {
  const tmpl = attackTemplatesStore.byId(id)
  if (!tmpl) {
    toast.warning('Failed to open editor - template was null')
    return
  }

  switch (tmpl.type) {
    case AttackTemplateType: {
      if (tmpl.hashcat_params == null) {
        toast.warning('Failed to open editor - settings were null')
        return
      }
      attackTemplateToEditId.value = tmpl.id
      isEditModalOpen.value = true
      break
    }

    case AttackTemplateSetType: {
      attackTemplateSetToEditId.value = tmpl.id
      isEditSetModalOpen.value = true
      break
    }
  }
}

async function onDeleteAttackTemplate(id: string) {
  try {
    await attackTemplatesStore.delete(id)
  } catch (e) {
    catcher(e, 'Failed to delete attack template')
  }
}
</script>

<template>
  <Modal v-model:isOpen="isCreateModalOpen">
    <AttackTemplateCreator @onCreated="() => (isCreateModalOpen = false)" />
  </Modal>

  <Modal v-model:isOpen="isCreateSetModalOpen">
    <AttackTemplateSetCreator @onCreated="() => (isCreateSetModalOpen = false)" />
  </Modal>

  <Modal v-model:isOpen="isEditModalOpen">
    <AttackTemplateEditor :idToEdit="attackTemplateToEditId" @onSaved="() => (isEditModalOpen = false)" />
  </Modal>

  <Modal v-model:isOpen="isEditSetModalOpen">
    <AttackTemplateSetEditor :idToEdit="attackTemplateSetToEditId" @onSaved="() => (isEditSetModalOpen = false)" />
  </Modal>

  <main class="w-full h-full p-4">
    <PageLoading v-if="isFirstLoading" />
    <div v-else>
      <h1 class="text-4xl font-bold">Attack Templates</h1>
      <div class="mt-6 flex flex-wrap gap-6">
        <div class="card min-w-[800px] bg-base-100 shadow-xl">
          <div class="card-body">
            <div class="flex flex-row justify-between">
              <h2 class="card-title">Attack Templates</h2>
              <div>
                <button class="btn btn-primary btn-sm ml-1" @click="() => (isCreateModalOpen = true)">
                  New Template <font-awesome-icon :icon="Icons.AttackTemplate" />
                </button>
                <button class="btn btn-primary btn-sm ml-1" @click="() => (isCreateSetModalOpen = true)" :disabled="templates.length === 0">
                  New Template Set
                  <font-awesome-icon :icon="Icons.AttackTemplateSet" />
                </button>
              </div>
            </div>
            <table class="table w-full">
              <thead>
                <tr>
                  <th class="w-0">Type</th>
                  <th>Name</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="tmpl in templates" :key="tmpl.id">
                  <td>
                    <div class="tooltip" data-tip="Attack Template" v-if="tmpl.type === AttackTemplateType">
                      <font-awesome-icon :icon="Icons.AttackTemplate" />
                    </div>
                    <div class="tooltip" data-tip="Template Set" v-if="tmpl.type === AttackTemplateSetType">
                      <font-awesome-icon :icon="Icons.AttackTemplateSet" />
                    </div>
                  </td>
                  <td>
                    {{ tmpl.name }}
                  </td>
                  <td>
                    <div>
                      <IconButton @click="() => onOpenEditAttackSettings(tmpl.id)" :icon="Icons.Edit" color="primary" tooltip="Edit" />
                      <ConfirmModal @on-confirm="() => onDeleteAttackTemplate(tmpl.id)">
                        <IconButton :icon="Icons.Delete" color="error" tooltip="Delete" />
                      </ConfirmModal>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
            <EmptyTable v-if="templates.length == 0" text="No Attack Templates Yet" :icon="Icons.AttackTemplate" />
          </div>
        </div>
      </div>
    </div>
  </main>
</template>
