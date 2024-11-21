<script setup lang="ts">
import { computed, reactive, watch } from 'vue'
import { useToast } from 'vue-toastification'
import { storeToRefs } from 'pinia'

import { AuthMethodCredentials, AuthMethodOIDC } from '@/api/config'
import type { AdminConfigRequestDTO, AuthOIDCConfigDTO, GeneralAuthConfigDTO } from '@/api/types'

import { useToastError } from '@/composables/useToastError'

import { useConfigStore } from '@/stores/config'
import { useAdminConfigStore } from '@/stores/adminConfig'

import { Icons } from '@/util/icons'

const configStore = useConfigStore()
const adminConfigStore = useAdminConfigStore()
const { config: adminConfig } = storeToRefs(adminConfigStore)
adminConfigStore.load()

const initialGeneral = adminConfigStore.config?.auth?.general
const initialOIDC = adminConfigStore.config?.auth?.oidc

const generalAuthSettings = reactive({
  enable_cred_login: initialGeneral?.enabled_methods.includes(AuthMethodCredentials),
  enable_oidc_login: initialGeneral?.enabled_methods.includes(AuthMethodOIDC),
  is_mfa_required: initialGeneral?.is_mfa_required ?? false,
  require_password_change_on_first_login: initialGeneral?.require_password_change_on_first_login ?? false
})

const oidcAuthSettings = reactive({
  client_id: initialOIDC?.client_id ?? '',
  client_secret: initialOIDC?.client_secret ?? '',

  issuer_url: initialOIDC?.issuer_url ?? '',
  base_url: initialOIDC?.redirect_url.replace('/oidc-callback', '') ?? '',

  automatic_user_creation: initialOIDC?.automatic_user_creation ?? false,
  username_claim: initialOIDC?.username_claim ?? '',
  prompt: initialOIDC?.prompt ?? '',

  roles_claim: initialOIDC?.role_field ?? '',
  required_role: initialOIDC?.required_role ?? '',

  additional_scopes: initialOIDC?.scopes.join(',') ?? ''
})

const validationError = computed<string | null>(() => {
  if (!generalAuthSettings.enable_cred_login && !generalAuthSettings.enable_oidc_login) {
    return 'One auth method must be enabled'
  }

  return null
})

watch(adminConfig, newSettings => {
  const general = newSettings?.auth?.general
  const oidc = newSettings?.auth?.oidc

  if (general != null) {
    generalAuthSettings.enable_cred_login = general.enabled_methods.includes(AuthMethodCredentials)
    generalAuthSettings.enable_oidc_login = general.enabled_methods.includes(AuthMethodOIDC)
    generalAuthSettings.is_mfa_required = general.is_mfa_required
    generalAuthSettings.require_password_change_on_first_login = general.require_password_change_on_first_login
  }

  if (oidc != null) {
    oidcAuthSettings.client_id = oidc.client_id
    oidcAuthSettings.client_secret = oidc.client_secret
    oidcAuthSettings.issuer_url = oidc.issuer_url
    oidcAuthSettings.base_url = oidc.redirect_url.replace('/oidc-callback', '')
    oidcAuthSettings.automatic_user_creation = oidc.automatic_user_creation
    oidcAuthSettings.username_claim = oidc.username_claim
    oidcAuthSettings.prompt = oidc.prompt
    oidcAuthSettings.roles_claim = oidc.role_field
    oidcAuthSettings.required_role = oidc.required_role
    oidcAuthSettings.additional_scopes = oidc.scopes.join(',')
  }
})

const toast = useToast()
const { catcher } = useToastError()

const displayRedirectURL = computed(() => oidcAuthSettings.base_url + '/oidc-callback')

function autoFillBaseURL() {
  oidcAuthSettings.base_url = window.location.origin
}

function copyRedirectURL() {
  navigator.clipboard.writeText(displayRedirectURL.value)
  toast.success('Copied!')
}

async function onSave() {
  const general: GeneralAuthConfigDTO = {
    enabled_methods: [
      ...(generalAuthSettings.enable_cred_login ? [AuthMethodCredentials] : []),
      ...(generalAuthSettings.enable_oidc_login ? [AuthMethodOIDC] : [])
    ],

    is_mfa_required: generalAuthSettings.is_mfa_required,
    require_password_change_on_first_login: generalAuthSettings.require_password_change_on_first_login
  }

  const oidc: AuthOIDCConfigDTO = {
    client_id: oidcAuthSettings.client_id,
    client_secret: oidcAuthSettings.client_secret,
    issuer_url: oidcAuthSettings.issuer_url,
    redirect_url: displayRedirectURL.value,
    automatic_user_creation: oidcAuthSettings.automatic_user_creation,
    username_claim: oidcAuthSettings.username_claim,
    prompt: oidcAuthSettings.prompt,
    role_field: oidcAuthSettings.roles_claim,
    required_role: oidcAuthSettings.required_role,
    scopes: oidcAuthSettings.additional_scopes.split(/,\s*/)
  }

  const update: AdminConfigRequestDTO = {
    auth: { general, oidc }
  }

  try {
    await adminConfigStore.update(update)
    configStore.load()
    toast.success('Settings saved')
  } catch (e: any) {
    catcher(e)
  } finally {
    adminConfigStore.load()
  }
}
</script>

<template>
  <table class="compact-table table-first-col-bold table">
    <thead>
      <tr>
        <th>Setting</th>
        <th class="w-[200px]">Value</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>Enable username/password login</td>
        <td><input type="checkbox" v-model="generalAuthSettings.enable_cred_login" class="toggle" /></td>
      </tr>

      <tr>
        <td>Require password change on first login</td>
        <td><input type="checkbox" v-model="generalAuthSettings.require_password_change_on_first_login" class="toggle" /></td>
      </tr>

      <tr>
        <td>Enable Single-Sign On (OIDC)</td>
        <td><input type="checkbox" v-model="generalAuthSettings.enable_oidc_login" class="toggle" /></td>
      </tr>

      <tr>
        <td>Require MFA (WebAuthn)</td>
        <td><input type="checkbox" class="toggle" /></td>
      </tr>

      <tr v-if="!generalAuthSettings.enable_oidc_login">
        <td></td>
        <td>
          <span class="tooltip" :data-tip="validationError"
            ><button class="btn btn-primary btn-sm" @click="() => onSave()" :disabled="adminConfigStore.loading || validationError != null">
              Save
            </button></span
          >
        </td>
      </tr>
    </tbody>
  </table>

  <div v-if="generalAuthSettings.enable_oidc_login" class="mt-4">
    <h3 class="text-lg font-bold">OIDC Settings</h3>
    <table class="compact-table table-first-col-bold table">
      <thead>
        <tr>
          <th>Setting</th>
          <th class="w-[200px]">Value</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Client ID</td>
          <td><input type="text" class="input input-bordered input-sm" v-model="oidcAuthSettings.client_id" placeholder="1234" /></td>
        </tr>
        <tr>
          <td>Client Secret</td>
          <td>
            <input type="password" class="input input-bordered input-sm" v-model="oidcAuthSettings.client_secret" placeholder="1234" />
          </td>
        </tr>

        <tr>
          <td>Issuer URL</td>
          <td>
            <input type="text" class="input input-bordered input-sm" v-model="oidcAuthSettings.issuer_url" placeholder="https://sso.lan" />
          </td>
        </tr>
        <tr></tr>
        <tr>
          <td>Base URL</td>
          <td>
            <span class="relative block">
              <input
                type="text"
                class="input input-bordered input-sm block"
                v-model="oidcAuthSettings.base_url"
                placeholder="https://phatcrack.lan"
              />
              <span
                class="tooltip absolute right-0 top-0"
                data-tip="Fill out based on current URL"
                v-if="oidcAuthSettings.base_url.length == 0"
              >
                <button class="btn btn-ghost btn-sm" @click="autoFillBaseURL">
                  <font-awesome-icon :icon="Icons.Autofill"></font-awesome-icon>
                </button>
              </span>
            </span>
          </td>
        </tr>

        <tr>
          <td>Redirect URL</td>
          <td class="max-w-[200px] whitespace-nowrap">
            <span
              class="tooltip w-full cursor-pointer"
              v-if="oidcAuthSettings.base_url != ''"
              data-tip="Click to copy"
              @click="copyRedirectURL"
            >
              <p class="overflow-hidden text-ellipsis whitespace-nowrap font-mono text-xs">{{ displayRedirectURL }}</p>
            </span>
            <p v-else>-</p>
          </td>
        </tr>

        <tr>
          <td>UI Prompt to Sign-in</td>
          <td>
            <input type="text" class="input input-bordered input-sm" v-model="oidcAuthSettings.prompt" placeholder="Log in with SSO" />
          </td>
        </tr>

        <tr>
          <td>Automatically create user on first login?</td>
          <td><input type="checkbox" class="toggle" v-model="oidcAuthSettings.automatic_user_creation" /></td>
        </tr>
        <tr>
          <td>Name of Username Claim</td>
          <td><input type="text" class="input input-bordered input-sm" v-model="oidcAuthSettings.username_claim" placeholder="email" /></td>
        </tr>
        <tr>
          <td>Name of Role Claim (optional, only if requiring a role)</td>
          <td>
            <input type="password" class="input input-bordered input-sm" v-model="oidcAuthSettings.roles_claim" placeholder="roles" />
          </td>
        </tr>
        <tr>
          <td>Required Role (optional, leave blank to allow all SSO users)</td>
          <td>
            <input
              type="text"
              class="input input-bordered input-sm"
              v-model="oidcAuthSettings.required_role"
              placeholder="phatcrack_user"
            />
          </td>
        </tr>

        <tr>
          <td>Additional Scopes (optional, comma separated)</td>
          <td>
            <input
              type="text"
              class="input input-bordered input-sm"
              v-model="oidcAuthSettings.additional_scopes"
              placeholder="microprofile-jwt"
            />
          </td>
        </tr>

        <tr v-if="generalAuthSettings.enable_oidc_login">
          <td></td>
          <td>
            <span class="tooltip" :data-tip="validationError"
              ><button
                class="btn btn-primary btn-sm"
                @click="() => onSave()"
                :disabled="adminConfigStore.loading || validationError != null"
              >
                Save
              </button></span
            >
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
<!-- 
<style scoped>
tr th:last-of-type {
  text-align: center;
}

tr td:last-of-type {
  text-align: center;
}
</style> -->
