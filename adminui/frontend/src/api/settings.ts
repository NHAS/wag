import type {
  GenericResponseDTO,
  MFAMethodDTO,
  LoginSettingsResponseDTO,
  GeneralSettingsResponseDTO,
  AcmeDetailsDTO,
  WebServerConfigDTO
} from './types'

import { client } from '.'

export function getGeneralSettings(): Promise<GeneralSettingsResponseDTO> {
  return client.get('/api/settings/general').then(res => res.data)
}

export function updateGeneralSettings(settings: GeneralSettingsResponseDTO): Promise<GenericResponseDTO> {
  return client.put('/api/settings/general', settings).then(res => res.data)
}

export function getLoginSettings(): Promise<LoginSettingsResponseDTO> {
  return client.get('/api/settings/login').then(res => res.data)
}

export function updateLoginSettings(settings: LoginSettingsResponseDTO): Promise<GenericResponseDTO> {
  return client.put('/api/settings/login', settings).then(res => res.data)
}

export function getMFAMethods(): Promise<MFAMethodDTO[]> {
  return client.get('/api/settings/all_mfa_methods').then(res => res.data)
}

export function getWebservers(): Promise<WebServerConfigDTO[]> {
  return client.get('/api/settings/webservers').then(res => res.data)
}

export function editWebserver(webserver: WebServerConfigDTO): Promise<GenericResponseDTO> {
  return client.put('/api/settings/webserver', webserver).then(res => res.data)
}

export function getAcmeDetails(): Promise<AcmeDetailsDTO> {
  return client.get('/api/settings/acme').then(res => res.data)
}

export function setAcmeEmail(email: string): Promise<GenericResponseDTO> {
  return client.put('/api/settings/acme/email', { data: email }).then(res => res.data)
}

export function setAcmeProvider(url: string): Promise<GenericResponseDTO> {
  return client.put('/api/settings/acme/provider_url', { data: url }).then(res => res.data)
}

export function setAcmeCloudflareDNSKey(cloudflare_api_key: string): Promise<GenericResponseDTO> {
  return client.put('/api/settings/acme/cloudflare_api_key', { data: cloudflare_api_key }).then(res => res.data)
}
