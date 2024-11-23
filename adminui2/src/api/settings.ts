import type { GenericResponseDTO, MFAMethodDTO, LoginSettingsResponseDTO, GeneralSettingsResponseDTO } from './types'

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
