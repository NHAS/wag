<script setup lang="ts">
import { ref } from 'vue';
import type {Ref, PropType} from 'vue';

const props = defineProps({
    helpMail: String,
    loading: Boolean,
})

const emit = defineEmits<{
  (e: 'submit', password: string): void
}>()

const password = ref('');
const showPassword = ref(false);

const togglePasswordVisibility = () => {
  showPassword.value = !showPassword.value;
};


</script>
<template>
     <!-- Header Section -->
  <h3 class="text-2xl font-bold text-center">Verify Your Identity</h3>
  <div class="divider my-1"></div>

  <!-- Description -->
  <p class="text-lg text-center mb-6">
    To access restricted resources, please verify your identity by entering your password below.
  </p>

  <!-- Form Section -->
  <form @submit.prevent='emit("submit", password)'>
    <div class="form-control">
      <div class="relative">
        <input v-model="password" autocomplete="off" :type="showPassword ? 'text' : 'password'" class="input text-neutral input-bordered w-full pr-10"
          placeholder="Enter your password" autofocus required />
        <button type="button" class="absolute top-1/2 right-3 -translate-y-1/2 btn btn-ghost btn-sm btn-circle"
          @click="togglePasswordVisibility">
          <i class="text-gray-500">
            {{ showPassword ? '👁️' : '👁️‍🗨️' }}
          </i>
        </button>
      </div>
    </div>

    <div class="form-control mt-6">
      <button type="submit" class="btn btn-primary" >
        <span class="loading loading-spinner" v-if="loading"></span>
        Verify Identity
      </button>
    </div>
  </form>

  <!-- Help Section -->
  <div class="mt-6 text-lg text-center">
    <p>Having trouble?</p>
    <a :href="'mailto:' + props.helpMail" class="link link-primary">
      Contact support at {{ props.helpMail }}
    </a>
  </div>
</template>