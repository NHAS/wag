import { defineStore } from "pinia";

import type { MFAMethod, UserInfoDTO } from "@/api/types";
import { apiGetInfo } from "@/api/info";

export type UserInfoState = {
  whoamiDetails: UserInfoDTO | null;

  isInfoLoading: boolean;
  loginError: string | null;
};

export const useInfoStore = defineStore({
  id: "info-store",

  state: () =>
    ({
      whoamiDetails: null,

      loginError: null,
      isInfoLoading: false,
    }) as UserInfoState,

  actions: {
    async load() {
      if (this.isInfoLoading) {
        return;
      }

      this.isInfoLoading = true;
      try {
        const details = await apiGetInfo();

        this.whoamiDetails = details;
        this.loginError = null;
      } catch (err: any) {
        this.whoamiDetails = null;
      } finally {
        this.isInfoLoading = false;
      }
    },
  },

  getters: {
    isLoggedIn: (state) => state.whoamiDetails?.is_authorized,
    loggedInUser: (state) => state.whoamiDetails?.username,

    user: (state) =>
      state.whoamiDetails ??
      ({
        available_mfa_methods: [] as MFAMethod[],
      } as UserInfoDTO),

    error: (state) => state.loginError,
  },
});
