import type { ClusterEvents, ClusterMember, AcknowledgeErrorResponseDTO, GenericResponseDTO } from './types'

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
