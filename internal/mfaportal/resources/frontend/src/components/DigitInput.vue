<script setup lang="ts">
import { nextTick, ref } from 'vue';
import type { PropType, Ref } from 'vue';


const props = defineProps({
    executionName: String,
    loading: Boolean,

})

const emit = defineEmits<{
    (e: 'submit', code: string): void
}>()


const digitInputs = ref<(HTMLInputElement | null)[]>([]);
const digits = ref(['', '', '', '', '', '']);

const submitButton = ref<HTMLButtonElement>()



function handleInput(index: number, event: KeyboardEvent): void {
    // Allow only numeric inputs and backspace
    if (event.key === 'Backspace') {

        nextTick(() => {

            let currentInput = digitInputs.value[index]
            if (currentInput == null) {
                return
            }
            currentInput.value = ""

            digits.value[index] = ""

            if (index > 0) {
                let input = digitInputs.value[index - 1]
                if (input == null) {
                    return
                }

                input.focus();
            }
        });
        event.preventDefault()

    } else if (/\d/.test(event.key) && event.key.length === 1) { // Ensure only single-digit keys
        digits.value[index] = event.key.toString(); // Direct assignment ensures only valid input

        nextTick(() => {
            if (index < 5) {
                digitInputs.value[index + 1]?.focus();
            } else {
                submitButton.value?.focus();
            }
        });
        event.preventDefault()
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
                        v-model="digits[index]" placeholder="0" @keydown="handleInput(index, $event)"
                        @paste="handlePaste($event)" autocomplete="off" />
                </template>
            </div>
        </div>
    </div>

    <div class="flex flex-col sm:flex-row gap-4">
        <button class="btn btn-primary flex-1" @click="emit('submit', digits.join(''))" ref="submitButton">
            {{ props.executionName }}
            <span class="loading loading-spinner" v-if="loading"></span>
        </button>
    </div>
</template>