<script setup lang="ts">
import { authoriseTotp, getTotpDetails, type MFARequest, type TOTPDetailsDTO, type TOTPRequestDTO } from "@/api";
import PageLoading from "@/components/PageLoading.vue";
import { useApi } from "@/composables/useApi";
import { useToastError } from "@/composables/useToastError";
import router from "@/router";
import { useInfoStore } from "@/store/info";
import { computed, ref } from "vue";
import { useToast } from "vue-toastification";

const infoStore = useInfoStore();

const { data: totp, isLoading: isLoadingTotpDetails } = useApi(() => getTotpDetails())

const isLoadingRegistrationDetails = computed(() => {
  return isLoadingTotpDetails.value
})

const totpDetails = computed(() => totp.value ?? {} as TOTPDetailsDTO)


const code = ref('')

const toast = useToast()
const { catcher } = useToastError()

async function totpAction(isRegistration: boolean) {
  try {
    let data: TOTPRequestDTO = {
      code: code.value
    }

    const resp = await authoriseTotp(data, isRegistration)

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      router.push("/success")
    }
  } catch (e) {
    catcher(e, 'failed to apply action: ')
  }
}


</script>

<template>
  <template v-if="infoStore.user.has_registered">
    <h4 class="card-title text-center">MFA Code</h4>

    <div class="max-w-[400px]">
      <p>
        In order to access restricted resources you must verify your identity.
        Please enter your MFA code below. If you are encountering issues, please
        send an email to
        <a :href="'mailto:' + infoStore.user.helpmail">{{
          infoStore.user.helpmail
        }}</a>.
      </p>
      <div class="flex items-center justify-center mb-8 mt-8">
        <label class="label font-bold text-neutral-content">
          <input type="text" class="input input-bordered text-center text-neutral" maxlength="6" autofocus
            placeholder="000000" v-mode="code"/>
        </label>
      </div>
      <button class="btn btn-primary w-full" @click="() => totpAction(false)" >Submit</button>
    </div>
  </template>
  <template v-else>
    <PageLoading v-if="isLoadingRegistrationDetails"></PageLoading>
    <template v-else>
      <h4 class="card-title justify-center mb-4">Configure mobile app</h4>
      <ol class="list-none">
        <li>Install Google Authenticator.</li>
        <li>In the app, tap the + symbol and choose "Scan a QR code".</li>
        <li>Scan the image below.</li>
        <li>Enter Code and hit submit</li>
      </ol>
      <div class="w-full justify-center flex mt-4 mb-4">
        <img class="w-[200px] h-[200px]" :src="totpDetails.qrcode" />
      </div>

      <p>
        If you are unable to scan this image, select "Enter a setup key" and enter the following information.
      </p>

      <div class="font-bold">Account name: {{ totpDetails.account_name }}</div>
      <div class="font-bold">Your key: {{ totpDetails.key }}</div>
      <div class="font-bold">Type of key: Time based</div>


      <div class="flex items-center justify-center mb-8 mt-8">
        <label class="label font-bold text-neutral-content">
          <input type="text" class="input input-bordered text-center text-neutral" maxlength="6" autofocus
            placeholder="000000" v-mode="code"/>
        </label>
      </div>
      <button class="btn btn-primary w-full" @click="() => totpAction(true)">Submit</button>

      <router-link to="/" v-if="infoStore.user.available_mfa_methods.length > 1">
        <button class="btn btn-primary">Use another method</button>
      </router-link>
    </template>

  </template>
</template>
