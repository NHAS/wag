import type { AuthLoginResponseDTO } from './types'

import { client } from '.'

export function loginWithCredentials(username: string, password: string): Promise<AuthLoginResponseDTO> {
  return client
    .post('/api/login', {
      username,
      password
    })
    .then(res => res.data)
}

export function apiRefreshAuth(): Promise<AuthLoginResponseDTO> {
  return client.post('/api/refresh').then(res => res.data)
}



export function logout() {
  return client.get('/api/logout')
}
