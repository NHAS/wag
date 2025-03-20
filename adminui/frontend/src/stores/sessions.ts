import { defineStore } from 'pinia'

import type { SessionDTO } from '@/api/types'
import { getAllSessions } from '@/api'

export type SessionsStore = {
  sessions: SessionDTO[] | null
  loading: boolean
}

export const useSessionsStore = defineStore({
  id: 'sessions-store',

  state: () =>
    ({
      sessions: [] as SessionDTO[],
      loading: false
    }) as SessionsStore,

  actions: {
    async load(forceRefetch = false) {
      if (this.loading) {
        return
      }

      if (forceRefetch || this.sessions == null) {
        this.loading = true
        try {
          this.sessions = await getAllSessions()
        } finally {
          this.loading = false
        }
      }
    }
  },

  getters: {
    deviceActive: state => (address: string) => state.sessions?.some(x => x.address == address) ?? false,
    byUser: state => (username: string) => state.sessions?.find(x => x.username == username) ?? [],
    numSessions: state => () => state.sessions?.length ?? 0,
  }
})
