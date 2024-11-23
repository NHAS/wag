import { defineStore } from 'pinia'

import { loginWithCredentials as apiLogin, logout as apiLogout, apiRefreshAuth } from '@/api/auth'
import type { AuthLoginResponseDTO } from '@/api/types'

import { setCSRFHeader } from '@/api'

export type AuthState = {
  whoamiDetails: AuthLoginResponseDTO | null

  isLoginLoading: boolean
  loginError: string | null
  hasTriedAuth: boolean
  hasLoggedOut: boolean
  isRefreshing: boolean
  csrfToken: string
  csrfHeader: string
}

export const useAuthStore = defineStore({
  id: 'auth-store',

  state: () =>
    ({
      whoamiDetails: null,

      loginError: null,
      isLoginLoading: false,

      // When the app first loads, we don't want to assume a session timeout, so we want to check auth at least once
      hasTriedAuth: false,
      hasLoggedOut: false,
      isRefreshing: false
    }) as AuthState,

  actions: {
    async login(username: string, password: string): Promise<boolean> {
      this.isLoginLoading = true
      try {
        const details = await apiLogin(username, password)
        this.whoamiDetails = details
        this.loginError = null

        // set csrf header name and content on success
        setCSRFHeader(details.csrfToken, details.csrfHeader)
      } catch (err: any) {
        this.whoamiDetails = null
        this.loginError = 'Failed to login'
      } finally {
        this.hasTriedAuth = true
        this.isLoginLoading = false
      }

      return this.loggedInUser != null
    },

    async logout() {
      try {
        await apiLogout()
      } finally {
        this.hasLoggedOut = true
        this.loginError = ''
        this.whoamiDetails = null
      }
    },

    async refreshAuth() {
      if (this.isRefreshing) {
        return
      }
      this.isRefreshing = true

      try {
        const details = await apiRefreshAuth()
        setCSRFHeader(details.csrfToken, details.csrfHeader)

        this.whoamiDetails = details
        this.loginError = null
      } catch (err: any) {
        // We were logged in before, and now we're not
        if (this.loggedInUser != null) {
          if (this.hasLoggedOut) {
            // Did we click logout? if so, reset and don't show a session timeout
            this.hasLoggedOut = false
            this.loginError = ''
          } else {
            // Otherwise, probably a session timeout
            this.loginError = 'Session timeout'
          }
        } else if (err?.response?.status == 401) {
          this.loginError = 'Logged out'
        } else {
          this.loginError = 'Unknown Error'
        }

        this.whoamiDetails = null
      } finally {
        this.hasTriedAuth = true
        this.isRefreshing = false
      }
    }
  },

  getters: {
    isLoggedIn: state => state.whoamiDetails?.user != null,
    loggedInUser: state => state.whoamiDetails?.user,

    hasCompletedAuth: state => state.whoamiDetails?.user != null && !state.whoamiDetails.user.change,

    username: state => state.whoamiDetails?.user.username,

    error: state => state.loginError,
    csrfToken: state => state.csrfToken,
    csrfHeader: state => state.csrfHeader
  }
})
