<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { ref, computed, watch } from 'vue'
import { useToast } from 'vue-toastification'

import { useToastError } from '@/composables/useToastError'

import { useAuthStore } from '@/stores/auth'
import {  getMFAMethods, getGeneralSettings, getLoginSettings, updateGeneralSettings, updateLoginSettings, type GeneralSettingsResponseDTO as GeneralSettingsDTO, type LoginSettingsResponseDTO as LoginSettingsDTO } from '@/api'
import { useApi } from '@/composables/useApi'
import PageLoading from '@/components/PageLoading.vue'
import { type MFAMethodDTO } from '@/api'

const authStore = useAuthStore()
const { loggedInUser } = storeToRefs(authStore)


const toast = useToast()
const { catcher } = useToastError()

const { data: general, isLoading: isLoadingGeneralSettings, silentlyRefresh: refreshGeneral } = useApi(() => getGeneralSettings())
const { data: loginSettings, isLoading: isLoadingLoginSettings, silentlyRefresh: refreshLoginSettings } = useApi(() => getLoginSettings())

const { data: mfaTypes, isLoading: isLoadingMFATypes } = useApi(() => getMFAMethods())

const generalData = computed(() => general.value ?? {} as GeneralSettingsDTO)
const loginSettingsData = computed(() => loginSettings.value ?? {} as LoginSettingsDTO)

const textValue = ref(general.value?.dns.join('\n') ?? '')

watch(textValue, (newValue) => {
  if (general.value) {
    general.value.dns = newValue.split('\n').filter(item => item.trim() !== '')
  }
})

watch(general, (newValue) => {
  if (newValue) {
    textValue.value = newValue.dns.join('\n')
  }
})

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
    refreshLoginSettings()

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      toast.success('Saved login settings')
    }
  } catch (e) {
    catcher(e, 'failed to save login settings: ')
  }
}

function filterMfaMethods(enabledMethods: string[], allMethods: MFAMethodDTO[]): MFAMethodDTO[] {
  return allMethods.filter((x) => enabledMethods.indexOf(x.method) != -1)
}


</script>

<template>
  <main class="w-full p-4">
    <PageLoading v-if="isLoadingGeneralSettings || isLoadingLoginSettings || isLoadingMFATypes" />

    <div v-else>
      <h1 class="text-4xl font-bold">Settings</h1>
      <div class="mt-6 flex flex-wrap gap-6">
        <div class="flex flex-wrap w-full gap-4">
          <div class="card bg-base-100 shadow-xl min-w-[350px]">
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
                  v-model="textValue"></textarea>
              </div>

              <div class="flex flex-grow"></div>

              <button type="submit" class="btn btn-primary w-full" @click="() => saveGeneralSettings()">
                <span class="loading loading-spinner loading-md" v-if="isLoadingGeneralSettings"></span>
                Save
              </button>
            </div>
          </div>
          <div class="card bg-base-100 shadow-xl min-w-[350px]">
            <div class="card-body">
              <h2 class="card-title">Login</h2>

              <div class="form-control">
                <label class="label font-bold">
                  <span class="label-text">Session Life Time (Minutes)</span>
                </label>
                <input v-model="loginSettingsData.max_session_lifetime_minutes" type="number"
                  class="input input-bordered w-full" />
              </div>

              <div class="form-control">
                <label class="label font-bold">
                  <span class="label-text">Inactivity Timeout (Minutes)</span>
                </label>
                <input v-model="loginSettingsData.session_inactivity_timeout_minutes" type="number"
                  class="input input-bordered w-full" />
              </div>

              <div class="form-control">
                <label class="label font-bold">
                  <span class="label-text">Max Authentication Attempts</span>
                </label>
                <input v-model="loginSettingsData.lockout" type="number" class="input input-bordered w-full" />
              </div>

              <div class="form-control w-full">
                <label for="default_method" class="label font-bold">Default MFA Method</label>
                <select class="select select-bordered " name="default_method"
                  v-model="loginSettingsData.default_mfa_method">
                  <option v-for="method in filterMfaMethods(loginSettingsData.enabled_mfa_methods, mfaTypes ?? [])"
                    :selected="method.method == loginSettingsData.default_mfa_method" :value="method.method">{{ method.friendly_name }}</option>
                </select>
              </div>

              <div class="flex flex-col">
                <div v-for="method in mfaTypes" class="form-control w-full">
                  <label :for=method.method class="label cursor-pointer">
                    <span class="label-text">{{ method.friendly_name }}</span>
                    <span class="flex flex-grow"></span>
                    <span v-if="method.method == loginSettingsData.default_mfa_method" class="text-gray-400 mr-4">DEFAULT</span>
                    <input :name=method.method type="checkbox" class="toggle toggle-primary" :value="method.method"
                      v-model="loginSettingsData.enabled_mfa_methods"
                      :checked="loginSettingsData.enabled_mfa_methods.indexOf(method.method) != -1" />
                  </label>
                </div>
              </div>

              <div class="flex flex-grow"></div>

              <button type="submit" class="btn btn-primary w-full" @click="() => saveLoginSettings()">
                <span class="loading loading-spinner loading-md" v-if="isLoadingLoginSettings"></span>
                Save
              </button>
            </div>
          </div>

          <div>
            <div
              v-if="loginSettingsData.enabled_mfa_methods.indexOf('totp') != -1 || loginSettingsData.enabled_mfa_methods.indexOf('webauthn') != -1"
              class="card bg-base-100 shadow-xl min-w-[350px] h-max mb-4">
              <div class="card-body">
                <h2 class="card-title">Login > General</h2>

                <div class="form-control">
                  <label class="label font-bold">
                    <span class="label-text">Issuer</span>
                  </label>
                  <input v-model="loginSettingsData.issuer" type="text" required class="input input-bordered w-full" />
                </div>
                <div class="form-control">
                  <label class="label font-bold">
                    <span class="label-text">Internal VPN Domain</span>
                  </label>
                  <input v-model="loginSettingsData.domain" type="text" required class="input input-bordered w-full" />
                </div>
              </div>
            </div>

            <div v-if="loginSettingsData.enabled_mfa_methods.indexOf('pam') != -1"
              class="card bg-base-100 shadow-xl min-w-[350px] h-max">
              <div class="card-body">
                <h2 class="card-title">Login > System Login</h2>

                <div class="form-control">
                  <label class="label font-bold">
                    <span class="label-text">Service Name</span>
                  </label>
                  <input v-model="loginSettingsData.pam.service_name" type="text" required
                    class="input input-bordered w-full" />
                </div>
              </div>
            </div>
          </div>

          <div v-if="loginSettingsData.enabled_mfa_methods.indexOf('oidc') != -1"
            class="card bg-base-100 shadow-xl min-w-[350px] h-max">
            <div class="card-body">
              <h2 class="card-title">Login > SSO Settings</h2>

              <div class="form-control">
                <label class="label font-bold">
                  <span class="label-text">Provider URL</span>
                </label>
                <input v-model="loginSettingsData.oidc.issuer" type="text" required
                  class="input input-bordered w-full" />
              </div>

              <div class="form-control">
                <label class="label font-bold">
                  <span class="label-text">Client ID</span>
                </label>
                <input v-model="loginSettingsData.oidc.client_id" type="text" required
                  class="input input-bordered w-full" />
              </div>

              <div class="form-control">
                <label class="label font-bold">
                  <span class="label-text">Client Secret</span>
                </label>
                <input v-model="loginSettingsData.oidc.client_secret" type="password" required
                  class="input input-bordered w-full" />
              </div>

              <div class="form-control">
                <label class="label font-bold">
                  <span class="label-text">Groups Claim Name</span>
                </label>
                <input v-model="loginSettingsData.oidc.group_claim_name" type="text"
                  class="input input-bordered w-full" />
              </div>

              <div class="form-control">
                <label class="label font-bold">
                  <span class="label-text">Device Username Claim</span>
                </label>
                <input v-model="loginSettingsData.oidc.device_username_claim" type="text"
                  class="input input-bordered w-full" />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>
</template>
