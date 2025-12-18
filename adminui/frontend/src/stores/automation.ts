import { defineStore } from 'pinia'

import type { WebhookGetResponseDTO } from '@/api/types'

import { getAllWebhooks } from '@/api'

export type WebhooksToken = {
  hooks: WebhookGetResponseDTO[]
  loading: boolean
}

export const useWebhooksStore = defineStore({
  id: 'webhooks-store',

  state: () =>
    ({
      hooks: [],
      loading: false
    }) as WebhooksToken,

  actions: {
    async load(forceRefetch: boolean = false) {
      if ((this.hooks.length > 0 || this.loading) && !forceRefetch) {
        return
      }

      try {
        this.loading = true
        this.hooks = await getAllWebhooks()
      } finally {
        this.loading = false
      }
    }
  }
})
