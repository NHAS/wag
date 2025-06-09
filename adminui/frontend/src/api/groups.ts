import type { GroupDTO, GroupCreateDTO, GroupEditDTO, GenericResponseDTO } from './types'

import { client } from '.'

export function getAllGroups(): Promise<GroupDTO[]> {
  return client.get('/api/policy/groups').then(res => res.data)
}

export function editGroup(groupUpdates: GroupEditDTO): Promise<GenericResponseDTO> {
  return client.put('/api/policy/groups', groupUpdates).then(res => res.data)
}

export function createGroup(group: GroupCreateDTO): Promise<GenericResponseDTO> {
  return client.post('/api/policy/groups', group).then(res => res.data)
}

export function deleteGroups(groups: string[]): Promise<GenericResponseDTO> {
  return client.delete('/api/policy/groups', { data: groups }).then(res => res.data)
}
