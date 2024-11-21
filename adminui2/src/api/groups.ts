import type { GroupDTO, GenericResponseDTO } from './types'

import { client } from '.'

export function getAllGroups(): Promise<GroupDTO[]> {
  return client.get('/api/policy/groups').then(res => res.data)
}

export function editGroup(updatedGroup: GroupDTO): Promise<GenericResponseDTO> {
  return client.put('/api/policy/groups', updatedGroup).then(res => res.data)
}

export function createGroup(group: GroupDTO): Promise<GenericResponseDTO> {
  return client.post('/api/policy/groups', group).then(res => res.data)
}


export function deleteGroups(groups: string[]): Promise<GenericResponseDTO> {
  return client.delete('/api/policy/groups', {data: groups}).then(res => res.data)
}


