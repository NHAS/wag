import type { GenericResponseDTO, WebhookCreateRequestDTO, WebhookGetResponseDTO } from './types'

import { client } from '.'

export function getAllWebhooks(): Promise<WebhookGetResponseDTO[]> {
  return client.get('/api/management/webhooks').then(res => res.data)
}

export function getWebhookLastRequest(id: string): Promise<GenericResponseDTO> {
  return client.post('/api/management/webhook/request', {id}).then(res => res.data)
}


export function createWebhook(webhook: WebhookCreateRequestDTO): Promise<GenericResponseDTO> {
  return client.post('/api/management/webhooks', webhook).then(res => res.data)
}

export function deleteWebhooks(webhook: string[]): Promise<GenericResponseDTO> {
  return client.delete('/api/management/webhooks', { data: webhook }).then(res => res.data)
}


