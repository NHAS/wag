import type { EditDevicesDTO, GenericResponseDTO, DeviceDTO } from './types'

import { client } from '.'

export function getAllDevices(): Promise<DeviceDTO[]> {
  return client.get('/api/management/devices').then(res => res.data)
}

export function editDevice(device: EditDevicesDTO): Promise<GenericResponseDTO> {
  return client.put('/api/management/devices', device).then(res => res.data)
}

export function deleteDevice(address: string): Promise<GenericResponseDTO> {
  return client.delete('/api/management/devices', { data: [address] }).then(res => res.data)
}

export function deleteDevices(addresses: string[]): Promise<GenericResponseDTO> {
  return client.delete('/api/management/devices', { data: addresses }).then(res => res.data)
}
