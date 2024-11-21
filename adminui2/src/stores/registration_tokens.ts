import { defineStore } from 'pinia'

import { getAllRegistrationTokens } from '@/api/registration_tokens'
import type { RegistrationToken } from '@/api/types'

export type RegistrationTokensStore = {
  tokens: RegistrationToken[]
  loading: boolean
}

export const useTokensStore = defineStore({
  id: 'registration-tokens-store',

  state: () =>
    ({
      tokens: [],
      loading: false
    }) as RegistrationTokensStore,

  actions: {
    async load(forceRefetch: boolean = false) {
      if ((this.tokens.length > 0 || this.loading) && !forceRefetch) {
        return
      }

      try {
        this.loading = true
        this.tokens = await getAllRegistrationTokens()
      } finally {
        this.loading = false
      }
    }
  }
})
