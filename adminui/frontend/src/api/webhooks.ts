import type { GenericResponseDTO, WebhookDTO } from './types'

import { client } from '.'

export function getAllWebhooks(): Promise<WebhookDTO[]> {
  return client.get('/api/management/webhooks').then(res => res.data)
}

export function getWebhookLastRequest(): Promise<GenericResponseDTO> {
  return client.get('/api/management/webhook/request').then(res => res.data)
}


export function createWebhook(webhook: WebhookDTO): Promise<GenericResponseDTO> {
  return client.post('/api/management/webhooks', webhook).then(res => res.data)
}

export function deleteWebhooks(webhook: string[]): Promise<GenericResponseDTO> {
  return client.delete('/api/management/webhooks', { data: webhook }).then(res => res.data)
}


