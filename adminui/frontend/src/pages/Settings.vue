<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useToast } from 'vue-toastification'

import PageLoading from '@/components/PageLoading.vue'
import ConfirmModal from '@/components/ConfirmModal.vue'
import { X509Certificate } from "@peculiar/x509";
import { useToastError } from '@/composables/useToastError'
import { useApi } from '@/composables/useApi'

import {
  getMFAMethods,
  getGeneralSettings,
  getLoginSettings,
  updateGeneralSettings,
  updateLoginSettings,
  type GeneralSettingsResponseDTO as GeneralSettingsDTO,
  type LoginSettingsResponseDTO as LoginSettingsDTO,
  type WebServerConfigDTO,
  type MFAMethodDTO,
  getAcmeDetails,
  type AcmeDetailsDTO,
  setAcmeCloudflareDNSKey,
  setAcmeEmail,
  setAcmeProvider,
  getWebservers,
  editWebserver,
  type ServerInfoDTO
} from '@/api'
import { Icons } from '@/util/icons'
import { copyToClipboard } from '@/util/clipboard'

const toast = useToast()
const { catcher } = useToastError()

const apiTokenSetValue = '**********'

const { data: acme, isLoading: isLoadingAcmeSettings, silentlyRefresh: refreshAcme } = useApi(() => getAcmeDetails())
const { data: general, isLoading: isLoadingGeneralSettings, silentlyRefresh: refreshGeneral } = useApi(() => getGeneralSettings())
const { data: loginSettings, isLoading: isLoadingLoginSettings, silentlyRefresh: refreshLoginSettings } = useApi(() => getLoginSettings())
const { data: webservers, isLoading: isLoadingWebserverSettings, silentlyRefresh: refreshWebservers } = useApi(() => getWebservers())

const { data: mfaTypes, isLoading: isLoadingMFATypes } = useApi(() => getMFAMethods())

const originalAcmeStates = ref<AcmeDetailsDTO>({} as AcmeDetailsDTO)

watch(
  acme,
  newAcme => {
    if (newAcme) {
      originalAcmeStates.value = {
        api_token_set: newAcme.api_token_set,
        email: newAcme.email,
        provider_url: newAcme.provider_url
      }
    }
  },
  { immediate: true }
)

const originalServerStates = ref<Record<string, WebServerConfigDTO>>({})

watch(
  webservers,
  newServers => {
    if (newServers) {
      originalServerStates.value = newServers.reduce(
        (acc, server) => {
          acc[server.server_name] = {
            server_name: server.server_name,
            domain: server.domain,
            listen_address: server.listen_address,
            tls: server.tls,

            static_certificates: server.static_certificates,
            certificate: server.certificate,
            private_key: server.private_key

          }
          return acc
        },
        {} as Record<string, WebServerConfigDTO>
      )
    }
  },
  { immediate: true }
)

const getModifiedServers = () => {
  if (!webservers.value) return []

  return webservers.value.filter(server => {
    const original = originalServerStates.value[server.server_name]
    if (!original) return true // New server

    return original.domain !== server.domain ||
      original.listen_address !== server.listen_address ||
      original.tls !== server.tls ||
      original.static_certificates !== server.static_certificates ||
      original.private_key !== server.private_key ||
      original.certificate !== server.certificate

  })
}

async function saveServerSettings() {
  try {
    const updateResults = await Promise.all(getModifiedServers().map(server => editWebserver(server)))

    const allSuccessful = updateResults.every(result => result.success) // Adjust based on your API response structure
    if (allSuccessful) {
      toast.success('updated servers!')
    } else {
      const failedServers = updateResults.filter(resp => resp.success)
      toast.error('failed to save server settings' + failedServers.map(s => s.message))
    }
  } catch (e) {
    catcher(e, 'failed to save acme settings: ')
  } finally {
    refreshWebservers()
  }
}

const generalData = computed(
  () =>
    general.value ??
    ({
      dns: [] as string[]
    } as GeneralSettingsDTO)
)
const loginSettingsData = computed(() => loginSettings.value ?? ({} as LoginSettingsDTO))
const acmeSettingsData = computed(() => acme.value ?? ({} as AcmeDetailsDTO))

const webserversSettingsData = computed(() => webservers.value ?? ([] as WebServerConfigDTO[]))

const textValue = ref(general.value?.dns.join('\n') ?? '')

watch(textValue, newValue => {
  if (general.value) {
    general.value.dns = newValue.split('\n').filter(item => item.trim() !== '')
  }
})

watch(general, newValue => {
  if (newValue) {
    textValue.value = newValue.dns?.join('\n') ?? ''
  }
})

const cloudflareApiTokenRef = ref('')
watch(acme, newVal => {
  if (newVal?.api_token_set) {
    cloudflareApiTokenRef.value = apiTokenSetValue
  } else {
    cloudflareApiTokenRef.value = ''
  }
})

async function saveAcmeSettings() {
  try {
    let failed = false

    if (cloudflareApiTokenRef.value !== apiTokenSetValue) {
      const resp = await setAcmeCloudflareDNSKey(cloudflareApiTokenRef.value)
      if (!resp.success) {
        toast.error('Failed to save cloudflare api token:' + (resp.message ?? 'Unknown Error'))
        failed = true
      }
    }

    if (acmeSettingsData.value.email != originalAcmeStates.value.email) {
      const resp = await setAcmeEmail(acmeSettingsData.value.email)
      if (!resp.success) {
        toast.error('Failed to save acme email:' + (resp.message ?? 'Unknown Error'))
        failed = true
      }
    }

    if (acmeSettingsData.value.provider_url != originalAcmeStates.value.provider_url) {
      const resp = await setAcmeProvider(acmeSettingsData.value.provider_url)
      if (!resp.success) {
        toast.error('Failed to save acme provider url:' + (resp.message ?? 'Unknown Error'))
        failed = true
      }
    }

    if (!failed) {
      toast.success('Saved acme settings')
    }
  } catch (e) {
    catcher(e, 'failed to save acme settings: ')
  } finally {
    refreshAcme()
  }
}

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
  return allMethods.filter(x => enabledMethods.indexOf(x.method) != -1)
}

function isAcmeValid(): boolean {
  return acmeSettingsData.value.email.length > 0 && acmeSettingsData.value.provider_url.length > 0
}

function serverCanHaveTLS(domain: string): boolean {
  return isAcmeValid() && domain.length > 0
}

function doesTunnelHaveDomain() {
  return webserversSettingsData.value.some(x => x.server_name == 'tunnel' && x.domain.length > 0)
}

function doesTunnelHaveTLS() {
  return webserversSettingsData.value.some(x => x.server_name == 'tunnel' && x.tls)
}


function makeSSOCallbackURL() {

  let scheme = "http://"
  if (doesTunnelHaveTLS()) {
    scheme = "https://"
  }

  let tunnelWebServer = webserversSettingsData.value.find(x => x.server_name == "tunnel")
  if (tunnelWebServer === undefined || tunnelWebServer === null) {
    return "N/A"
  }

  let host = tunnelWebServer.domain
  if (tunnelWebServer.domain == "") {
    host = tunnelWebServer.listen_address
  }

  let path = scheme + host + "/api/oidc/authorise/callback"
  return path
}



const readFileAsText = (file: File): Promise<string> => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()

    reader.onload = (event) => {
      const result = event.target?.result
      if (typeof result === 'string') {
        resolve(result)
      } else {
        reject(new Error('Failed to read file as text'))
      }
    }

    reader.onerror = () => {
      reject(new Error('File reading failed'))
    }

    reader.readAsText(file)
  })
}

function parseCert(cert: string): string {
  try {
    const parsedCert = new X509Certificate(cert);
    return parsedCert.subject
  } catch (e) {
    return "Bad certificate"
  }
}

function determineTLSMethodText(server: WebServerConfigDTO): string {
    if(!server.tls) {
      return "Disabled"
    }

    const validAcme = acmeSettingsData.value.email.length !== 0 && acmeSettingsData.value.provider_url.length !== 0

    if(!server.static_certificates) {
      if(validAcme) {
        return acmeSettingsData.value.api_token_set ? "DNS-01" : "HTTP-01"
      }
      return "Invalid ACME"
    }

    return "Custom Certificates"
}

const activeTab = ref('general')


</script>

<template>
  <main class="w-full p-4">
    <PageLoading
      v-if="isLoadingGeneralSettings || isLoadingLoginSettings || isLoadingMFATypes || isLoadingAcmeSettings || isLoadingWebserverSettings" />

    <div v-else>
      <h1 class="text-4xl font-bold">Settings</h1>

      <div class="mt-6 flex flex-wrap gap-6">

        <!-- Tab Navigation -->
        <div class="tabs tabs-boxed">
          <a class="tab" :class="{ 'tab-active': activeTab === 'general', 'font-bold': activeTab === 'general' }"
            @click="activeTab = 'general'">
            General
          </a>
          <a class="tab"
            :class="{ 'tab-active': activeTab === 'authentication', 'font-bold': activeTab === 'authentication' }"
            @click="activeTab = 'authentication'">
            Authentication
          </a>
          <a class="tab" :class="{ 'tab-active': activeTab === 'webservers', 'font-bold': activeTab === 'webservers' }"
            @click="activeTab = 'webservers'">
            Web Servers
          </a>
        </div>

        <div class="flex flex-wrap w-full gap-4">
          <div v-if="activeTab === 'general'" class="flex flex-wrap w-full gap-4">


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
                  <label for="dns" class="block font-medium label-text pt-6">DNS</label>
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
          </div>
          <div v-else-if="activeTab === 'authentication'" class="flex flex-wrap w-full gap-4">
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
                  <select class="select select-bordered" name="default_method"
                    v-model="loginSettingsData.default_mfa_method"
                    :disabled="loginSettingsData.enabled_mfa_methods.length == 0">
                    <option v-for="method in filterMfaMethods(loginSettingsData.enabled_mfa_methods, mfaTypes ?? [])"
                      :selected="method.method == loginSettingsData.default_mfa_method" :value="method.method"
                      :key="method.method">
                      {{ method.friendly_name }}
                    </option>
                  </select>
                </div>

                <div class="flex flex-col">
                  <div v-for="method in mfaTypes" class="form-control w-full" :key="method.method">
                    <label :for="method.method" class="label cursor-pointer">
                      <span class="label-text" :key="method.method">{{ method.friendly_name }}</span>
                      <span class="flex flex-grow"></span>
                      <span
                        v-if="method.method == loginSettingsData.default_mfa_method && loginSettingsData.enabled_mfa_methods.length > 0"
                        class="opacity-60 mr-4">DEFAULT</span>

                      <div class="tooltip"
                        :data-tip="(!doesTunnelHaveDomain() && (method.method == 'oidc' || method.method == 'webauthn')) ? 'This method requires that the tunnel has a domain' : (!doesTunnelHaveTLS() && method.method == 'webauthn') ? 'The tunnel requires TLS to use this authentication method' : null">
                        <input :name="method.method" type="checkbox" class="toggle toggle-primary"
                          :value="method.method" v-model="loginSettingsData.enabled_mfa_methods" :disabled="(!doesTunnelHaveDomain() && (method.method == 'oidc' || method.method == 'webauthn')) ||
                            (!doesTunnelHaveTLS() && method.method == 'webauthn')
                            " :checked="loginSettingsData.enabled_mfa_methods.indexOf(method.method) != -1" />
                      </div>
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
              <div v-if="
                loginSettingsData.enabled_mfa_methods.indexOf('totp') != -1 ||
                loginSettingsData.enabled_mfa_methods.indexOf('webauthn') != -1
              " class="card bg-base-100 shadow-xl min-w-[350px] h-max mb-4">
                <div class="card-body">
                  <h2 class="card-title">Login > General</h2>

                  <div class="form-control">
                    <label class="label font-bold">
                      <span class="label-text">Issuer</span>
                    </label>
                    <input v-model="loginSettingsData.issuer" type="text" required
                      class="input input-bordered w-full" />
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
              class="card bg-base-100 shadow-xl min-w-[350px] max-w-[400px] h-max">
              <div class="card-body">
                <h2 class="card-title">Login > SSO Settings</h2>

                <div class="relative">
                  <label class="label font-bold">
                    <span class="label-text">Callback</span>
                  </label>
                  <div class="overflow-hidden text-ellipsis whitespace-nowrap mr-6">
                    {{ makeSSOCallbackURL() }}
                  </div>
                  <button @click="copyToClipboard(makeSSOCallbackURL())" class="absolute right-0 top-9 opacity-100">
                    <font-awesome-icon :icon="Icons.Clipboard" class="text-secondary" />
                  </button>
                </div>

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
                <div class="form-control">
                  <label class="label font-bold">
                    <span class="label-text">Scopes</span>
                  </label>
                  <input :value="loginSettingsData.oidc.scopes?.join(' ')"
                    @input="e => loginSettingsData.oidc.scopes = (e.target as HTMLInputElement).value.split(' ')"
                    type="text" class="input input-bordered w-full" placeholder="Enter scopes separated by spaces" />
                </div>
              </div>
            </div>
          </div>

          <div v-else-if="activeTab === 'webservers'" class="flex flex-wrap w-full gap-4">

            <div class="card bg-base-100 shadow-xl min-w-[700px] max-w-[700px]">
              <div class="card-body">
                <h2 class="card-title mb-4">Web Servers</h2>

                <div role="tablist" class="tabs tabs-bordered w-full justify-center mb-4">
                  <template v-for="(server, index) in webserversSettingsData" :key="'webserver-' + server.server_name">
                    <input type="radio" name="webserver-tabs" role="tab" class="tab" :aria-label="server.server_name"
                      :checked="index == 0" />
                    <div role="tabpanel" class="tab-content p-10">

                      <div class="flex mb-2">
                        <p>TLS Method: </p>
                        <div class="flex flex-grow"></div>
                        <div class="tooltip" :data-tip="acmeSettingsData.email.length == 0 || acmeSettingsData.provider_url.length == 0
                          ? 'No ACME settings configured and no custom certificates uplodated'
                          : 'TLS Method'
                          ">
                          <p class="font-bold">
                            {{
                              determineTLSMethodText(server)
                            }}
                          </p>
                        </div>
                      </div>

                      <label class="label font-bold">
                        <span class="label-text">Domain</span>
                      </label>
                      <input v-model="server.domain" type="text" class="input input-bordered w-full" />

                      <template v-if="server.server_name == 'tunnel'">
                        <label class="label font-bold">
                          <span class="label-text">Port</span>
                        </label>
                        <input :value="server.listen_address.split(':')[1] || ''" @input="
                          (e: Event) => {
                            const [host] = server.listen_address.split(':')
                            server.listen_address = `${host}:${(e.target as HTMLInputElement).value}`
                          }
                        " type="number" class="input input-bordered w-full" />
                      </template>
                      <template v-else>
                        <label class="label font-bold">
                          <span class="label-text">Listen Address</span>
                        </label>
                        <input v-model="server.listen_address" type="text" class="input input-bordered w-full" />
                      </template>


                      <label class="label font-bold">
                        <span class="label-text">Custom Certificates</span>
                        <input v-model="server.static_certificates" type="checkbox" class="toggle toggle-primary" />

                      </label>

                      <template v-if="server.static_certificates">
                        <div class="form-control">
                          <label class="label font-bold" for="certificate">
                            <span class="truncate max-w-[350px] min-w-[350px]">{{
                              server.certificate == "" ? "Please add certificate" : parseCert(server.certificate)
                            }}</span>
                            <span class="label-text btn">{{ server.certificate === "" ? "Add Certificate" : "Change Certificate"}}</span>
                          </label>
                          <input type="file" id="certificate" class="hidden" accept=".crt,.pem,.cert" @change="async (e: Event) => {
                            const target = e.target as HTMLInputElement
                            const file = target.files?.[0]

                            if (!file) {
                              return
                            }

                            try {
                              // Check file size (16KB = 16 * 1024 bytes)
                              const maxSize = 16 * 1024
                              if (file.size > maxSize) {
                                toast.error('Certificate exceeds maximum size of 16kb')
                                return
                              }

                              // Read the file content
                              const fileContent = await readFileAsText(file)
                              server.certificate = fileContent


                            } catch (error) {
                              toast.error('Error reading file:' + error)
                            }
                          }" />

                        </div>

                        <div class="form-control">
                          <label class="label font-bold" for="privateKey">
                            <span class="w-full">{{ server.private_key === "Valid"? "Valid Private Key" : server.private_key.length > 0 ? "" : "Please add private key" }}</span>
                            <span class="label-text btn">{{ server.private_key.length > 0? "Change Private Key" : "Add Private Key" }}</span>
                          </label>
                          <input type="file" id="privateKey" class="hidden" accept=".key,.pem" @change="async (e: Event) => {
                            const target = e.target as HTMLInputElement
                            const file = target.files?.[0]

                            if (!file) {
                              return
                            }

                            try {
                              // Check file size (16KB = 16 * 1024 bytes)
                              const maxSize = 16 * 1024
                              if (file.size > maxSize) {
                                toast.error('Private key exceeds maximum size of 16kb')
                                return
                              }

                              // Read the file content
                              const fileContent = await readFileAsText(file)
                              server.private_key = fileContent


                            } catch (error) {
                              toast.error('Error reading file:' + error)
                            }
                          }" />
                        </div>

                        <div class="alert alert-warning mt-4 mb-2">
                          <div class="text-sm">
                            <strong>Note:</strong> Uploaded certificates will override ACME certificates.
                            Make sure your certificate matches your domain configuration.
                          </div>
                        </div>
                      </template>


                      <label class="label font-bold">
                        <span class="label-text">TLS</span>
                        <span :class="serverCanHaveTLS(server.domain) || server.static_certificates ? '' : 'tooltip'"
                          data-tip="Domain name required and either customer certificates or ACME configuration must be valid">
                          <input v-model="server.tls" type="checkbox" class="toggle toggle-primary"
                            :disabled="!serverCanHaveTLS(server.domain) && !server.tls && !server.static_certificates" />
                        </span>
                      </label>
                    </div>
                  </template>
                </div>
                <ConfirmModal v-if="getModifiedServers().some(s => s.server_name == 'management')"
                  @on-cancel="refreshWebservers" @on-confirm="saveServerSettings"
                  body="Editing the management interface may stop you from being able to manage Wag, are you sure you want to proceed?">
                  <button type="submit" class="btn btn-primary w-full">
                    <span class="loading loading-spinner loading-md" v-if="isLoadingWebserverSettings"></span>
                    Save
                  </button>
                </ConfirmModal>
                <button v-else type="submit" class="btn btn-primary w-full" @click="saveServerSettings">
                  <span class="loading loading-spinner loading-md" v-if="isLoadingWebserverSettings"></span>
                  Save
                </button>
              </div>
            </div>

            <div class="card bg-base-100 shadow-xl min-w-[350px] h-max">
              <div class="card-body">
                <h2 class="card-title">ACME</h2>

                <div class="form-control">
                  <label class="label font-bold">
                    <span class="label-text">E-Mail</span>
                  </label>
                  <input v-model="acmeSettingsData.email" type="email" class="input input-bordered w-full" />
                </div>

                <div class="form-control">
                  <label class="label font-bold">
                    <span class="label-text">Provider</span>
                  </label>
                  <input v-model="acmeSettingsData.provider_url" type="url" class="input input-bordered w-full" />
                </div>

                <div class="form-control">
                  <label class="label font-bold">
                    <span class="label-text">Cloudflare API Token</span>
                  </label>
                  <input v-model="cloudflareApiTokenRef" type="password" class="input input-bordered w-full" />
                </div>

                <button type="submit" class="btn btn-primary w-full" @click="() => saveAcmeSettings()">
                  <span class="loading loading-spinner loading-md" v-if="isLoadingAcmeSettings"></span>
                  Save
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>
</template>
