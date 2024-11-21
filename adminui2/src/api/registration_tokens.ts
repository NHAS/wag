import type { RegistrationToken } from './types'

import { client } from '.'

export function getAllRegistrationTokens(): Promise<RegistrationToken[]> {
  return client.get('/api/management/registration_tokens').then(res => res.data)
}
