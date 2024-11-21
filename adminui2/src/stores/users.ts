import { defineStore } from 'pinia'

import type { UserDTO } from '@/api/types'
import { getAllUsers } from '@/api/users'

export type UsersState = {
  users: UserDTO[]
  isLoading: boolean
}

export const useUsersStore = defineStore({
  id: 'users-store',

  state: () =>
    ({
      users: [],
      isLoading: false
    }) as UsersState,

  actions: {
    async load(forceRefetch: boolean = false) {
      if ((this.users.length > 0 || this.isLoading) && !forceRefetch) {
        return
      }

      try {
        this.isLoading = true
        this.users = await getAllUsers()
      } finally {
        this.isLoading = false
      }
    }
  },

  getters: {
    byUsername: state => (username: string) => state.users.find(x => x.username === username) ?? null
  }
})
