import type { ClusterEvents, ClusterMember } from './types'

import { client } from '.'

export function getClusterEvents(): Promise<ClusterEvents> {
  return client.get('/api/cluster/events').then(res => res.data)
}

export function getClusterMembers(): Promise<ClusterMember[]> {
  return client.get('/api/cluster/members').then(res => res.data)
}
