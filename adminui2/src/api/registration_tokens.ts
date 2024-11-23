import type { GenericResponseDTO, RegistrationTokenRequestDTO } from './types'

import { client } from '.'

export function getAllRegistrationTokens(): Promise<RegistrationTokenRequestDTO[]> {
  return client.get('/api/management/registration_tokens').then(res => res.data)
}

export function createRegistrationToken(token: RegistrationTokenRequestDTO): Promise<GenericResponseDTO> {
  return client.post('/api/management/registration_tokens', token).then(res => res.data)
}

export function deleteRegistrationTokens(tokens: string[]): Promise<GenericResponseDTO> {
  return client.delete('/api/management/registration_tokens', { data: tokens }).then(res => res.data)
}
