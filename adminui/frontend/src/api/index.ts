import axios from 'axios'

export const client = axios.create()

client.interceptors.request.use(config => {
  return config
})

export function setCSRFHeader(csrfToken: string, csrfHeaderName: string) {
  client.defaults.headers.common[csrfHeaderName] = csrfToken
}

export * from './rules'
export * from './auth'
export * from './devices'
export * from './groups'
export * from './types'
export * from './users'
export * from './account'
export * from './server_info'
export * from './settings'
export * from './diagnostics'
export * from './config'
export * from './sessions'
export * from './webhooks'
