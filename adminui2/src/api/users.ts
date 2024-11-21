import type { UserDTO } from './types'

import { client } from '.'

export function getAllUsers(): Promise<UserDTO[]> {
  return client.get('/api/management/users').then(res => res.data)
}
