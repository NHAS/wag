import type { ConfigResponseDTO } from './types'

import { client } from '.'

export function getConfig(): Promise<ConfigResponseDTO> {
  return client.get('/api/config').then(res => res.data)
}