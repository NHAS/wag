<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useToast } from 'vue-toastification'

import IconButton from '@/components/IconButton.vue'
import Modal from '@/components/Modal.vue'
import FileUpload from '@/components/FileUpload.vue'
import EmptyTable from '@/components/EmptyTable.vue'
import ConfirmModal from '@/components/ConfirmModal.vue'
import CheckboxSet from '@/components/CheckboxSet.vue'

import type { DeviceDTO } from '@/api/types'
import { deleteDevice, type ListfileTypeT } from '@/api/devices'

import { useToastError } from '@/composables/useToastError'

import { useListfilesStore } from '@/stores/devices'
import { useAuthStore } from '@/stores/auth'

import { bytesToReadable } from '@/util/units'
import { Icons } from '@/util/icons'

const listfilesStore = useListfilesStore()
const { load: loadListfiles } = listfilesStore
const { groupedByType } = storeToRefs(listfilesStore)
const listfiles = computed(() => Object.values(groupedByType.value).flat())

const isListfileUploadOpen = ref(false)

const listfileTypes = {
  Rulefile: { icon: Icons.Rulefile },
  Wordlist: { icon: Icons.Wordlist },
  Charset: { icon: Icons.Charset }
} as { [key: string]: { icon: string } }

const listfileTypesFilter = ref(
  Object.fromEntries(
    Object.keys(listfileTypes)
      .map(x => [x, true])
      .concat([['Unknown', true]])
  )
)

const filteredListfiles = computed(() => {
  return listfiles.value.filter(x => listfileTypesFilter.value[x.file_type] ?? listfileTypesFilter.value['Unknown'] ?? true)
})

const getIconForType = (type: string) => listfileTypes[type]?.icon ?? Icons.Unknown

loadListfiles(true)

const refreshTimer = ref(0)

onMounted(() => {
  refreshTimer.value = setInterval(() => {
    loadListfiles(true)
  }, 1000 * 60)
})

onBeforeUnmount(() => {
  clearInterval(refreshTimer.value)
})

function speedUpRefresh() {
  clearInterval(refreshTimer.value)
  refreshTimer.value = setInterval(() => {
    loadListfiles(true)
  }, 1000 * 10)
}

const authStore = useAuthStore()
const { loggedInUser, isAdmin } = storeToRefs(authStore)

function canDelete(listfile: DeviceDTO) {
  if (listfile.pending_delete) {
    return false
  }

  if (isAdmin) {
    return true
  }
  return listfile.created_by_user_id == loggedInUser.value?.id
}

function isGreyed(listfile: DeviceDTO) {
  return listfile.pending_delete || !listfile.available_for_use
}

const toast = useToast()
const { catcher } = useToastError()

async function onDeleteListfile(listfile: DeviceDTO) {
  speedUpRefresh()
  try {
    await deleteDevice(listfile.id)
    toast.info(`Marked ${listfile.name} for deletion`)
  } catch (e: any) {
    catcher(e)
  } finally {
    loadListfiles(true)
  }
}
</script>

<template>
  <main class="w-full p-4">
    <h1 class="text-4xl font-bold">Listfiles</h1>
    <div class="mt-6 flex flex-wrap gap-6">
      <div class="card min-w-[800px] bg-base-100 shadow-xl">
        <div class="card-body">
          <div class="flex flex-row justify-between">
            <Modal v-model:isOpen="isListfileUploadOpen">
              <FileUpload @on-upload-finish="() => speedUpRefresh()" :allowed-file-types="Object.keys(listfileTypes) as ListfileTypeT[]" />
            </Modal>
            <h2 class="card-title">Listfiles</h2>

            <div>
              <div class="dropdown mr-2">
                <label tabindex="0" class="btn btn-sm">Filter</label>
                <ul tabindex="0" class="menu dropdown-content rounded-box z-[1] mt-1 min-w-[200px] bg-base-100 p-2 shadow">
                  <CheckboxSet v-model="listfileTypesFilter" />
                </ul>
              </div>
              <button class="btn btn-primary btn-sm" @click="() => (isListfileUploadOpen = true)">Upload Listfile</button>
            </div>
          </div>
          <table class="table w-full">
            <thead>
              <tr>
                <th>Type</th>
                <th>Name</th>
                <th>Size</th>
                <th>Lines</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr
                :class="isGreyed(listfile) ? 'greyed-out-row hover text-gray-500' : 'hover'"
                v-for="listfile in filteredListfiles"
                :key="listfile.id"
              >
                <td class="text-center">
                  <div class="tooltip" :data-tip="listfile.file_type">
                    <font-awesome-icon :icon="getIconForType(listfile.file_type)" />
                  </div>
                </td>
                <td>
                  <strong>{{ listfile.name }}</strong>
                  <span class="pl-2 text-sm text-gray-500" v-if="!listfile.available_for_use">
                    <div class="tooltip" data-tip="Syncing...">
                      <font-awesome-icon :icon="Icons.Awaiting" />
                    </div>
                  </span>
                  <span class="pl-2 text-sm text-gray-500" v-if="listfile.pending_delete">
                    <div class="tooltip" data-tip="Marked for death">
                      <font-awesome-icon :icon="Icons.Dead" title="" />
                    </div>
                  </span>
                </td>

                <td>{{ bytesToReadable(listfile.size_in_bytes) }}</td>
                <td>{{ listfile.lines }}</td>
                <td class="text-center">
                  <ConfirmModal @on-confirm="() => onDeleteListfile(listfile)" v-if="canDelete(listfile)">
                    <IconButton :icon="Icons.Delete" color="error" tooltip="Delete" />
                  </ConfirmModal>
                  <div v-else class="tooltip cursor-not-allowed text-gray-300" :data-tip="'You can\'t delete this'">
                    <button class="btn btn-ghost btn-xs cursor-not-allowed">
                      <font-awesome-icon :icon="Icons.Locked" />
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
          <EmptyTable v-if="listfiles.length == 0" text="No Listfiles Uploaded Yet" icon="fa-file" />
        </div>
      </div>
    </div>
  </main>
</template>

<style scoped>
.greyed-out-row strong {
  font-weight: normal;
}
</style>
