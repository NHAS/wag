<script setup lang="ts">
import { computed, ref } from 'vue'
import { useToast } from 'vue-toastification'

import PaginationControls from '@/components/PaginationControls.vue'
import ConfirmModal from '@/components/ConfirmModal.vue'
import RegistrationToken from '@/components/RegistrationToken.vue'

import { usePagination } from '@/composables/usePagination'
import { useToastError } from '@/composables/useToastError'

import { useRoute } from 'vue-router'
import { useDevicesStore } from '@/stores/devices'
import { Icons } from '@/util/icons'

import { deleteDevices, editDevice, DeviceEditActions, type EditDevicesDTO, type DeviceDTO } from '@/api'

const devicesStore = useDevicesStore()
devicesStore.load(false)

const route = useRoute()

const filterText = ref('')

const allDevices = computed(() => devicesStore.devices ?? [])


const filterActive = ref(route.params.filter == 'active')
const filterLocked = ref(route.params.filter == 'locked')

const filteredDevices = computed(() => {
  const arr = allDevices.value.filter(a => (a.active || !filterActive.value)).filter(a => a.is_locked || !filterLocked.value)

  if (filterText.value == '') {
    return arr
  }

  const searchTerm = filterText.value.trim().toLowerCase()

  return arr.filter(
    x =>
      x.internal_ip.toLowerCase().includes(searchTerm) ||
      x.last_endpoint?.includes(searchTerm) ||
      x.owner?.includes(searchTerm)
  )
})

const { next: nextPage, prev: prevPage, totalPages, currentItems: currentDevices, activePage } = usePagination(filteredDevices, 20)

const toast = useToast()
const { catcher } = useToastError()

async function updateDevice(addresses: string[], action: DeviceEditActions) {
  try {
    let data: EditDevicesDTO = {
      action: action,
      addresses: addresses
    }

    const resp = await editDevice(data)
    devicesStore.load(true)

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
  try {

    const resp = await deleteDevices(rules)
    devicesStore.load(true)

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

  if(lastSort.value == null || lastSort.value == by) {
    ascending.value = !ascending.value
  } else {
    ascending.value = true
    lastSort.value = by
  }

  if(devicesStore.devices) {
    devicesStore.devices.sort((a,b) => {
      const valueA = a[by];
      const valueB = b[by];
      const compair = valueA < valueB ? -1 : valueA > valueB ? 1 : 0;
      return ascending.value ? compair : -compair;
    })
  }
}

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
            <div class="tooltip" data-tip="Create Registration Token">
              <button class="btn btn-ghost btn-primary" @click="isCreateTokenModalOpen = true">Add Device <font-awesome-icon :icon="Icons.Add" /></button>
            </div>
            <span class="flex">
            <label class="label cursor-pointer mr-4">
              <span class="label-text mr-2">Locked</span>
              <input v-model=filterLocked type="checkbox" class="toggle toggle-primary"/>
            </label>
            <label class="label cursor-pointer mr-4">
              <span class="label-text mr-2">Active</span>
              <input v-model=filterActive type="checkbox" class="toggle toggle-primary"/>
            </label>
            <label class="label">
              <input type="text" class="input input-bordered input-sm" placeholder="Filter..." v-model="filterText" />
            </label>
          </span>
          </div>

          <table class="table table-fixed w-full">
            <thead>
              <tr>
                <th class="cursor-pointer" @click="sortDevices('owner')">Owner</th>
                <th class="cursor-pointer" @click="sortDevices('active')">Active</th>
                <th class="cursor-pointer" @click="sortDevices('internal_ip')">Address</th>
                <th class="cursor-pointer" @click="sortDevices('public_key')">Public Key</th>
                <th class="cursor-pointer" @click="sortDevices('last_endpoint')">Last Endpoint</th>
                <th class="cursor-pointer" @click="sortDevices('is_locked')">Locked</th>
              </tr>
            </thead>
            <tbody>
              <tr class="hover group" v-for="device in currentDevices" :key="device.internal_ip">
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ device.owner }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ device.active }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ device.internal_ip }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ device.public_key }}</div>
                </td>
                <td class="font-mono">
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ device.last_endpoint == '<nil>' ? '-'
                    : device.last_endpoint}}</div>

                </td>
                <td class="font-mono relative">
                  <div><font-awesome-icon class="cursor-pointer"
                      @click="updateDevice([device.internal_ip], (device.is_locked) ? DeviceEditActions.Unlock : DeviceEditActions.Lock)"
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
