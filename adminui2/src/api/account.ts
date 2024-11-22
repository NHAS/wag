import type { GenericResponseDTO, ChangePasswordRequestDTO } from './types'

import { client } from '.'

export function changePassword(credentials: ChangePasswordRequestDTO): Promise<GenericResponseDTO> {
  return client.put('/api/change_password', credentials).then(res => res.data)
}
