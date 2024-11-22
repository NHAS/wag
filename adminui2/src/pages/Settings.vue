<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { ref, computed } from 'vue'
import { useToast } from 'vue-toastification'

import { useToastError } from '@/composables/useToastError'

import { useAuthStore } from '@/stores/auth'
import { useTextareaInput } from '@/composables/useTextareaInput'
import { getGeneralSettings, getLoginSettings, updateGeneralSettings, updateLoginSettings, type GeneralSettingsResponseDTO as GeneralSettingsDTO, type LoginSettingsResponseDTO as LoginSettingsDTO } from '@/api'
import { useApi } from '@/composables/useApi'
import PageLoading from '@/components/PageLoading.vue'

const authStore = useAuthStore()
const { loggedInUser } = storeToRefs(authStore)


const toast = useToast()
const { catcher } = useToastError()

const { data: general, isLoading: isLoadingGeneralSettings, silentlyRefresh: refreshGeneral } = useApi(() => getGeneralSettings())
const { data: loginSettings, isLoading: isLoadingLoginSettings, silentlyRefresh: refreshLoginSettings } = useApi(() => getLoginSettings())


const generalData = computed(() => general.value ?? {} as GeneralSettingsDTO)
const loginSettingsData = computed(() => loginSettings.value ?? {} as LoginSettingsDTO)


const { Input: Dns, Arr: DnsArr } = useTextareaInput()

Dns.value = (general.value?.dns ?? []).join("\n")


async function saveGeneralSettings() {
  try {
    const resp = await updateGeneralSettings(generalData.value as GeneralSettingsDTO)
    refreshGeneral()

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      toast.success('Saved general settings')
    }
  } catch (e) {
    catcher(e, 'failed to save general settings: ')
  }
}

async function saveLoginSettings() {
  try {
    const resp = await updateLoginSettings(loginSettingsData.value as LoginSettingsDTO)
    refreshGeneral()

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      toast.success('Saved general settings')
    }
  } catch (e) {
    catcher(e, 'failed to save general settings: ')
  }
}


</script>

<template>
  <main class="w-full p-4">
    <PageLoading v-if="isLoadingGeneralSettings || isLoadingLoginSettings" />

    <div v-else>
      <h1 class="text-4xl font-bold">Settings</h1>
      <div class="mt-6 flex flex-wrap gap-6">
        <div class="flex w-full gap-4">
          <div class="card bg-base-100 shadow-xl min-w-[400px]">
            <div class="card-body">
              <h2 class="card-title">General</h2>

              <div class="form-control">
                <label class="label font-bold">
                  <span class="label-text">Help Mail</span>
                </label>
                <input v-model="generalData.help_mail" type="email" class="input input-bordered w-full" />
              </div>

              <div class="form-control">
                <label class="label font-bold">
                  <span class="label-text">External Wireguard Address</span>
                </label>
                <input v-model="generalData.external_address" type="text" class="input input-bordered w-full" />
              </div>

              <div class="form-control">
                <label class="label font-bold">
                  <span class="label-text">Wireguard Config Filename</span>
                </label>
                <input v-model="generalData.wireguard_config_filename" type="text" placeholder="hunter2"
                  class="input input-bordered w-full" />
              </div>

              <div class="form-control">
                <label for="dns" class="block font-medium text-gray-900 pt-6">DNS</label>
                <textarea class="rules-input textarea textarea-bordered w-full font-mono" rows="3"
                  v-model="Dns"></textarea>
              </div>


                <button type="submit" class="btn btn-primary w-full"
                  @click="() => saveGeneralSettings()">
                  <span class="loading loading-spinner loading-md" v-if="isLoadingGeneralSettings"></span>
                  Save
                </button>
            </div>
          </div>
          <div class="card bg-base-100 shadow-xl min-w-[400px]">
            <div class="card-body">
              <h2 class="card-title">Login</h2>

              <div class="form-control">
                <label class="label font-bold">
                  <span class="label-text">Session Life Time (Minutes)</span>
                </label>
                <input v-model="loginSettingsData.max_session_lifetime_minutes" type="number" class="input input-bordered w-full" />
              </div>

              <div class="form-control">
                <label class="label font-bold">
                  <span class="label-text">Inactivity Timeout (Minutes)</span>
                </label>
                <input v-model="loginSettingsData.session_inactivity_timeout_minutes" type="number" class="input input-bordered w-full" />
              </div>

              <div class="form-control">
                <label class="label font-bold">
                  <span class="label-text">Max Authentication Attempts</span>
                </label>
                <input v-model="loginSettingsData.lockout" type="number"
                  class="input input-bordered w-full" />
              </div>

                <button type="submit" class="btn btn-primary w-full"
                  @click="() => saveLoginSettings()">
                  <span class="loading loading-spinner loading-md" v-if="isLoadingLoginSettings"></span>
                  Save
                </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>
</template>
