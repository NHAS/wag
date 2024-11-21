<script setup lang="ts">
import { ref, computed, watch } from 'vue'

interface OptionT {
  value: string
  text: string
  icon?: string
  iconTooltip?: string
}

const props = defineProps<{
  modelValue: string
  placeholderText: string
  options: OptionT[]
}>()

const emit = defineEmits(['update:modelValue'])

function textForValue(val: string) {
  return props.options.find(x => x.value === val)?.text ?? ''
}

const inputText = ref(textForValue(props.modelValue))

watch(
  () => props.modelValue,
  newModelVal => {
    inputText.value = textForValue(newModelVal)
  }
)

const filteredOptions = computed(() => props.options.filter(x => x.text.toLowerCase().includes(inputText.value.toLowerCase())))

const optionsVisible = ref(false)

function selectOption(option: OptionT) {
  optionsVisible.value = false
  emit('update:modelValue', option.value)
  inputText.value = option.text
}

function focus() {
  optionsVisible.value = true
  inputText.value = ''
}

function unfocus() {
  optionsVisible.value = false
  inputText.value = textForValue(props.modelValue)
}
</script>

<template>
  <div class="relative">
    <input
      type="text"
      class="input input-bordered w-full cursor-pointer focus:outline-none"
      :placeholder="props.placeholderText"
      v-model="inputText"
      @focus="focus"
      @blur="unfocus"
    />
    <div v-if="optionsVisible" class="floating-dropdown-content absolute w-full border-solid border-black shadow-md">
      <div
        :key="option.value"
        :class="modelValue == option.value ? 'active' : ''"
        v-for="option in filteredOptions"
        class="dropdown-content-option hover mx-1 my-1 cursor-pointer px-2 py-1"
        @mousedown="selectOption(option)"
      >
        <div class="tooltip tooltip-right" v-if="option.icon != null && option.icon != ''" :data-tip="option.iconTooltip">
          <font-awesome-icon :icon="option.icon" class="mr-2" />
        </div>
        {{ option.text }}
      </div>
    </div>
  </div>
</template>

<style scoped>
.floating-dropdown-content {
  background: white;
  max-height: 400px;
  overflow-y: scroll;
  overflow-x: hidden;
  z-index: 9999;
}

.dropdown-content-option {
  width: 100%;
}

.dropdown-content-option:hover {
  background: #eee;
}

.dropdown-content-option.active {
  background: #ddd;
}
</style>
