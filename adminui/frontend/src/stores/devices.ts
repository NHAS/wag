import { defineStore } from 'pinia'

import { getAllDevices } from '@/api/devices'
import type { DeviceDTO } from '@/api/types'

export type DevicesStore = {
  devices: DeviceDTO[]
  loading: boolean
}

export const useDevicesStore = defineStore({
  id: 'devices-store',

  state: () =>
    ({
      devices: [] as DeviceDTO[],
      loading: false
    }) as DevicesStore,

  actions: {
    async load(forceRefetch = false) {
      if (this.loading) {
        return
      }

      if (forceRefetch || this.devices.length === 0) {
        this.loading = true
        try {
          this.devices = await getAllDevices()
        } finally {
          this.loading = false
        }
      }
    }
  },

  getters: {
    byAddress: state => (address: string) => state.devices.find(x => x.internal_ip == address),
    byOwner: state => (owner: string) => state.devices.find(x => x.owner == owner),
    numDevices: state => () => state.devices?.length ?? 0,
    numActive: state => () => state.devices?.filter(x => x.active).length ?? 0
  }
})
