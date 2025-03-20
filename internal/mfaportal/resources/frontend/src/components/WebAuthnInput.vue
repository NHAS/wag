<script setup lang="ts">
import type { PropType, Ref } from 'vue';


const props = defineProps({
    helpMail: String,
    title: String,
    buttonLabel: String,
    loading: Boolean,

})

const emit = defineEmits(["submit"])

</script>
<template>
    <div class="text-center max-w-md mx-auto">
        <h3 class="text-2xl font-bold mb-4">{{ props.title }}</h3>
        <div class="divider"></div>

        <div class="flex justify-center mb-6">
            <div class="w-20 h-20 bg-primary bg-opacity-10 rounded-full flex items-center justify-center">
                <font-awesome-icon :icon="['fa-solid', 'shield-halved']" class="text-3xl text-primary" />
            </div>
        </div>

        <p class="mb-6">
            Please insert your security key and tap it when prompted by your browser.
        </p>

        <div class="p-4 rounded-lg mb-6">
            <div class="flex items-center gap-3">
                <font-awesome-icon :icon="['fa-solid', 'circle-info']" class="text-info" />
                <div class="text-sm text-left">
                    Having trouble? Contact support at <a :href="'mailto:' + props.helpMail"
                        class="link link-primary">
                        {{ props.helpMail }}
                    </a>
                </div>
            </div>
        </div>

        <button class="btn btn-primary w-full gap-2 text-base" autofocus @click="emit('submit')">
            {{ props.buttonLabel }}
            <span class="loading loading-spinner" v-if="loading"></span>
        </button>
    </div>
</template>