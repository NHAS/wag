import axios from 'axios'

export const client = axios.create()

client.interceptors.request.use(config => {
  console.log('Request Headers:', config.headers)
  return config
})

export function setCSRFHeader(csrfToken: string, csrfHeaderName: string) {
  console.log('setting: ', csrfHeaderName, csrfToken)
  client.defaults.headers.common[csrfHeaderName] = csrfToken
}

export * from './rules'
export * from './auth'
export * from './devices'
export * from './groups'
export * from './types'
export * from './users'
export * from './server_info'
