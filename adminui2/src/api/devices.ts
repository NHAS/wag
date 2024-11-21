import type { GetAllDevicesDTO } from './types'

import { client } from '.'

export function getAllDevices(): Promise<GetAllDevicesDTO> {
  return client.get('/api/management/devices').then(res => res.data)
}

export function deleteDevice(address: string): Promise<string> {
  return client.delete('/api/management/devices', { data: [address] }).then(res => res.data)
}

export function deleteDevices(addresses: string[]): Promise<string> {
  return client.delete('/api/management/devices', { data: addresses }).then(res => res.data)
}
