import type { LogLinesDTO, ServerInfoDTO } from './types'

import { client } from '.'

export function getServerInfo(): Promise<ServerInfoDTO> {
  return client.get('/api/info').then(res => res.data)
}

export function getServerLogLines(): Promise<LogLinesDTO> {
  return client.get('/api/console_log').then(res => res.data)
}
