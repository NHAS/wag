import type {
  ClusterEvents,
  ClusterMember,
  AcknowledgeErrorResponseDTO,
  GenericResponseDTO,
  NewNodeRequestDTO,
  NewNodeResponseDTO,
  NodeControlRequestDTO
} from './types'

import { client } from '.'

export function getClusterEvents(): Promise<ClusterEvents> {
  return client.get('/api/cluster/events').then(res => res.data)
}

export function acknowledgeClusterError(error: AcknowledgeErrorResponseDTO): Promise<GenericResponseDTO> {
  return client.put('/api/cluster/events', error).then(res => res.data)
}

export function getClusterMembers(): Promise<ClusterMember[]> {
  return client.get('/api/cluster/members').then(res => res.data)
}

export function addClusterMember(newNode: NewNodeRequestDTO): Promise<NewNodeResponseDTO> {
  return client.post('/api/cluster/members', newNode).then(res => res.data)
}

export function editClusterMember(action: NodeControlRequestDTO): Promise<GenericResponseDTO> {
  return client.put('/api/cluster/members', action).then(res => res.data)
}
