import { defineStore } from 'pinia'

import type { ServerInfoDTO, LogLinesDTO } from '@/api/types'

import { getServerInfo, getServerLogLines } from '@/api'

export type ServerState = {
  instanceDetails: ServerInfoDTO | null
  logLines: LogLinesDTO | null
  loading: boolean
}

export const useInstanceDetailsStore = defineStore({
  id: 'server-info-store',

  state: () =>
    ({
      instanceDetails: null,
      logLines: null,
      loading: false
    }) as ServerState,

  actions: {
    async load(forceRefetch = false) {
      if (this.loading) {
        return
      }

      if (forceRefetch || this.instanceDetails === null || this.logLines === null) {
        this.loading = true
        try {
          if (this.instanceDetails === null) {
            this.instanceDetails = await getServerInfo()
          }
          this.logLines = await getServerLogLines()
        } finally {
          this.loading = false
        }
      }
    }
  },

  getters: {
    serverInfo: state => state.instanceDetails ?? ({} as ServerInfoDTO),
    log: state => state.logLines?.log_lines ?? []
  }
})
