<script setup lang="ts">
import { nextTick, ref } from 'vue';


const props = defineProps({
    executionName: String,
})

const emit = defineEmits<{
  (e: 'submit', code: string): void
}>()


const digitInputs = ref<(HTMLInputElement | null)[]>([]);
const digits = ref(['', '', '', '', '', '']);

const submitButton = ref<HTMLButtonElement>()

function moveToNextInput(index: number): void {
    digits.value[index] = digits.value[index].replace(/[^0-9]/g, '');

    if (digits.value[index] && index < 5) {
        nextTick(() => {
            digitInputs.value[index + 1]?.focus();
        });
    } else {
        nextTick(() => {
            submitButton.value?.focus()
        });
    }
}

function handleBackspace(index: number, event: KeyboardEvent): void {
    if (!digits.value[index] && index > 0 && event.key === 'Backspace') {
        nextTick(() => {
            digitInputs.value[index - 1]?.focus();
        });
    }
}

function handlePaste(event: ClipboardEvent): void {
    event.preventDefault();
    const pastedData = event.clipboardData?.getData('text') || '';
    const numericData = pastedData.replace(/[^0-9]/g, '').slice(0, 6);


    for (let i = 0; i < numericData.length && i < 6; i++) {
        digits.value[i] = numericData[i];
    }

    // Focus the next empty input or the last one
    const nextEmptyIndex = digits.value.findIndex(d => !d);
    if (nextEmptyIndex !== -1 && nextEmptyIndex < 6) {
        nextTick(() => {
            digitInputs.value[nextEmptyIndex]?.focus();
        });
    } else if (numericData.length > 0) {
        nextTick(() => {
            submitButton.value?.focus()
        });
    }
}
</script>

<template>
    <div class="form-control mb-6">
        <div class="flex flex-col items-center gap-2">
            <label class="label">
                <span class="label-text">Enter 6-digit code</span>
            </label>
            <div class="flex gap-2 justify-center">
                <template v-for="(_, index) in 6" :key="index">
                    <input type="text" :autofocus="index == 0"
                        class="input input-bordered text-neutral input-primary w-12 h-12 text-center text-lg font-mono"
                        maxlength="1" :ref="(el) => digitInputs[index] = (el as HTMLInputElement)"
                        v-model="digits[index]" @input="moveToNextInput(index)" placeholder="0"
                        @keydown.backspace="handleBackspace(index, $event)" @paste="handlePaste($event)" autocomplete="off"/>
                </template>
            </div>
        </div>
    </div>

    <div class="flex flex-col sm:flex-row gap-4">
      <button class="btn btn-primary flex-1" @click="emit('submit', digits.join(''))" ref="submitButton">
        {{ props.executionName }}
      </button>
    </div>
</template>