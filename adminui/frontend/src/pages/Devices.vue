<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useToast } from 'vue-toastification'
import { useRoute } from 'vue-router'

import PaginationControls from '@/components/PaginationControls.vue'
import ConfirmModal from '@/components/ConfirmModal.vue'
import RegistrationToken from '@/components/RegistrationToken.vue'
import EmptyTable from '@/components/EmptyTable.vue'

import { usePagination } from '@/composables/usePagination'
import { useToastError } from '@/composables/useToastError'

import { useDevicesStore } from '@/stores/devices'
import { useSessionsStore } from '@/stores/sessions'

import { Icons } from '@/util/icons'

import { deleteDevices, editDevice, DeviceEditActions, type EditDevicesDTO, type DeviceDTO } from '@/api'


const sessionStore = useSessionsStore()
sessionStore.load(true)

const devicesStore = useDevicesStore()
devicesStore.load(true)

const route = useRoute()

const filterText = ref('')

const selectedDevices = ref<string[]>([])

const allDevices = computed(() => devicesStore.devices ?? [])

const filterActive = ref(route.params.filter == 'active')
const filterLocked = ref(route.params.filter == 'locked')

const filteredDevices = computed(() => {

  const arr = allDevices.value.filter(a => (sessionStore.deviceActive(a.internal_ip) || !filterActive.value)).filter(a => a.is_locked || !filterLocked.value)

  if (filterText.value == '') {
    return arr
  }

    console.log('After status filters:', arr.length)

  const searchTerm = filterText.value.trim().toLowerCase()

  return arr.filter(
    x =>
      x.internal_ip.toLowerCase().includes(searchTerm) ||
      x.last_endpoint?.includes(searchTerm) ||
      x.owner?.includes(searchTerm) ||
      x.tag?.includes(searchTerm)
  )
})

const { next: nextPage, prev: prevPage, totalPages, currentItems: currentDevices, activePage } = usePagination(filteredDevices, 20)

const toast = useToast()
const { catcher } = useToastError()

async function updateDevices(addresses: string[], action: DeviceEditActions) {
  if (addresses.length == 0) {
    return
  }

  try {
    let data: EditDevicesDTO = {
      action: action,
      addresses: addresses
    }

    const resp = await editDevice(data)
    devicesStore.load(true)

    selectedDevices.value = []
    selectAll.value = false

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      toast.success('devices ' + addresses.join(", ") + ' edited!')
    }
  } catch (e) {
    catcher(e, 'failed to edit devicess: ')
  }
}

async function tryDeleteDevices(rules: string[]) {
  if (rules.length == 0) {
    return
  }

  try {

    const resp = await deleteDevices(rules)
    devicesStore.load(true)

    selectedDevices.value = []
    selectAll.value = false

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      toast.success('user ' + rules.join(", ") + ' deleted!')
    }
  } catch (e) {
    catcher(e, 'failed to delete user: ')
  }
}

const isCreateTokenModalOpen = ref(false)

const lastSort = ref<keyof DeviceDTO | null>(null)
const ascending = ref(true)

function sortDevices(by: keyof DeviceDTO) {

  if (lastSort.value == null || lastSort.value == by) {
    ascending.value = !ascending.value
  } else {
    ascending.value = true
    lastSort.value = by
  }

  if (devicesStore.devices) {
    devicesStore.devices.sort((a, b) => {
      const valueA = a[by];
      const valueB = b[by];
      const compair = valueA < valueB ? -1 : valueA > valueB ? 1 : 0;
      return ascending.value ? compair : -compair;
    })
  }
}



const selectAll = ref(false)

watch(selectAll, (newValue) => {
  if (newValue) {
    // Select all devices
    selectedDevices.value = currentDevices.value.map(d => d.internal_ip)
  } else {
    // Deselect all devices
    selectedDevices.value = []
  }
})

watch(selectedDevices, (newVal) => {
  if (newVal.length == 0) {
    selectAll.value = false
  }
})

const selectedDevicesHasLocked = computed(() => {
  if (selectedDevices.value.length == 0) {
    return false
  }

  return allDevices.value.some(i => selectedDevices.value.includes(i.internal_ip) && i.is_locked)
})

</script>

<template>

  <main class="w-full p-4">
    <RegistrationToken v-model:isOpen="isCreateTokenModalOpen"></RegistrationToken>

    <h1 class="text-4xl font-bold mb-4">Devices</h1>
    <p>
      Registered user devices
    </p>
    <div class="mt-6 flex flex-wrap gap-6">
      <div class="card w-full bg-base-100 shadow-xl min-w-[800px]">
        <div class="card-body">
          <div class="flex flex-row justify-between">
            <span class="flex">
              <div class="tooltip" data-tip="Create Registration Token">
                <button class="btn btn-ghost" @click="isCreateTokenModalOpen = true">Add Device
                  <font-awesome-icon :icon="Icons.Add" /></button>
              </div>
              <div :class="selectedDevices.length > 0 ? 'tooltip' : null"
                :data-tip="(selectedDevicesHasLocked ? 'Unlock ' : 'Lock ') + selectedDevices.length + ' devices'">
                <button
                :disabled="selectedDevices.length == 0"
                  @click="updateDevices(selectedDevices, selectedDevicesHasLocked ? DeviceEditActions.Unlock : DeviceEditActions.Lock)"
                  class="btn btn-ghost disabled:bg-white ">{{ selectedDevicesHasLocked ? 'Unlock' : 'Lock' }}
                  <font-awesome-icon :icon="selectedDevicesHasLocked ? Icons.Unlocked : Icons.Locked" /></button>
              </div>
              <div :class="selectedDevices.length > 0 ? 'tooltip' : null" :data-tip="'Delete ' + selectedDevices.length + ' devices'">
                <ConfirmModal @on-confirm="() => tryDeleteDevices(selectedDevices)">
                  <button :disabled="selectedDevices.length == 0" class="btn btn-ghost disabled:bg-white">Bulk Delete<font-awesome-icon
                      :icon="Icons.Delete" /></button>
                </ConfirmModal>
              </div>
            </span>


            <span class="flex">
              <label class="label cursor-pointer mr-4">
                <span class="label-text mr-2">Locked</span>
                <input v-model=filterLocked type="checkbox" class="toggle toggle-primary" />
              </label>
              <label class="label cursor-pointer mr-4">
                <span class="label-text mr-2">Active</span>
                <input v-model=filterActive type="checkbox" class="toggle toggle-primary" />
              </label>
              <label class="label">
                <input type="text" class="input input-bordered input-sm" placeholder="Filter..." v-model="filterText" />
              </label>
            </span>
          </div>
          <table class="table table-fixed w-full">
            <thead>
              <tr>
                <th class="w-10">
                  <input type="checkbox" class="checkbox" v-model="selectAll" />
                </th>
                <th class="cursor-pointer" @click="sortDevices('owner')">Owner</th>
                <th class="cursor-pointer" @click="sortDevices('internal_ip')">Address</th>
                <th class="cursor-pointer" @click="sortDevices('tag')">Tag</th>
                <th class="cursor-pointer" @click="sortDevices('public_key')">Public Key</th>
                <th class="cursor-pointer" @click="sortDevices('last_endpoint')">Last Endpoint</th>
                <th class="cursor-pointer" @click="sortDevices('is_locked')">Locked</th>
              </tr>
            </thead>
            <tbody>
              <tr class="hover group" v-for="device in currentDevices" :key="device.internal_ip">
                <th>
                  <input type="checkbox" class="checkbox" v-model="selectedDevices" :value="device.internal_ip" />
                </th>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ device.owner }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ device.internal_ip }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ device.tag }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ device.public_key }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ device.last_endpoint == '<nil>' ? '-'
                    : device.last_endpoint }}</div>

                </td>
                <td class="font-mono relative">
                  <div><font-awesome-icon class="cursor-pointer"
                      @click="updateDevices([device.internal_ip], (device.is_locked) ? DeviceEditActions.Unlock : DeviceEditActions.Lock)"
                      :icon="device.is_locked ? Icons.Locked : Icons.Unlocked"
                      :class="device.is_locked ? 'text-error' : 'text-secondary'" /></div>
                  <ConfirmModal @on-confirm="() => tryDeleteDevices([device.internal_ip])">
                    <button
                      class="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                      <font-awesome-icon :icon="Icons.Delete" class="text-error hover:text-error-focus" />
                    </button>
                  </ConfirmModal>
                </td>
              </tr>
            </tbody>
          </table>
          <EmptyTable v-if="allDevices.length == 0" text="No devices" />
          <EmptyTable v-if="allDevices.length != 0 && allDevices.length == 0" text="No matching devices" />


          <div class="mt-2 w-full text-center">
            <PaginationControls @next="() => nextPage()" @prev="() => prevPage()" :current-page="activePage"
              :total-pages="totalPages" />
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
