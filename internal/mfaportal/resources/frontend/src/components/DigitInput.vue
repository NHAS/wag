<script setup lang="ts">
import { ref } from "vue";

const props = defineProps({
  executionName: String,
  loading: Boolean,
});

const emit = defineEmits<{
  (e: "submit", code: string): void;
}>();

const code = ref("");
const codeInput = ref<HTMLInputElement>();

function numericCode(value: string): string {
  return value.replace(/[^0-9]/g, "").slice(0, 6);
}

function handleInput(event: Event): void {
  const input = event.target as HTMLInputElement;
  const value = numericCode(input.value);

  input.value = value;
  code.value = value;
}

function submit(): void {
  emit("submit", numericCode(codeInput.value?.value ?? code.value));
}
</script>

<template>
  <form method="post" @submit.prevent="submit">
    <div class="form-control mb-6">
      <div class="flex flex-col items-center gap-2">
        <label class="label" for="one-time-code">
          <span class="label-text">Enter 6-digit code</span>
        </label>
        <input
          id="one-time-code"
          name="one-time-code"
          type="text"
          inputmode="numeric"
          autocomplete="one-time-code"
          maxlength="6"
          pattern="[0-9]*"
          autofocus
          class="input input-bordered input-primary h-12 w-72 max-w-full pl-[0.75em] text-center font-mono text-2xl tracking-[0.75em] text-neutral"
          ref="codeInput"
          :value="code"
          placeholder="000000"
          @input="handleInput"
        />
      </div>
    </div>

    <div class="flex flex-col gap-4 sm:flex-row">
      <button class="btn btn-primary flex-1" type="submit">
        {{ props.executionName }}
        <span v-if="loading" class="loading loading-spinner"></span>
      </button>
    </div>
  </form>
</template>
