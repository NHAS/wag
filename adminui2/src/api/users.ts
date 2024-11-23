import type { GenericResponseDTO, UserDTO, EditUsersDTO, AdminUsersDTO } from './types'

import { client } from '.'

export function getAllUsers(): Promise<UserDTO[]> {
  return client.get('/api/management/users').then(res => res.data)
}

export function deleteUsers(users: string[]): Promise<GenericResponseDTO> {
  return client.delete('/api/management/users', { data: users }).then(res => res.data)
}

export function editUser(edit: EditUsersDTO): Promise<GenericResponseDTO> {
  return client.put('/api/management/users', edit).then(res => res.data)
}

export function getAdminUsers(): Promise<AdminUsersDTO[]> {
  return client.get('/api/management/admin_users').then(res => res.data)
}
