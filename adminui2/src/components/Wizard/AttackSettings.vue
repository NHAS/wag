<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { computed, watch } from 'vue'

import MaskInput from '@/components/Wizard/MaskInput.vue'
import WordlistSelect from '@/components/Wizard/ListSelect.vue'
import SearchableDropdown from '@/components/SearchableDropdown.vue'

import { AttackTemplateSetType, AttackTemplateType } from '@/api/attackTemplate'

import { useListfilesStore } from '@/stores/devices'
import { useAttackTemplatesStore } from '@/stores/attackTemplates'

import { AttackMode, attackModes, isLoopbackValid } from '@/util/hashcat'
import { Icons } from '@/util/icons'

export interface AttackSettingsT {
  attackMode: AttackMode

  selectedTemplateId: string

  selectedWordlists: string[]
  selectedRulefiles: string[]

  mask: string
  maskIncrement: boolean

  combinatorLeft: string[]
  combinatorRight: string[]

  optimizedKernels: boolean
  slowCandidates: boolean
  enableLoopback: boolean

  isDistributed: boolean
}

const props = defineProps<{
  modelValue: AttackSettingsT
  enableTemplate?: boolean
}>()

const emit = defineEmits(['update:modelValue'])

const attackSettings = computed({
  get: () => props.modelValue,
  set: newVal => emit('update:modelValue', newVal)
})

const availableAttackModes = computed(() => {
  if (props.enableTemplate) {
    return attackModes
  } else {
    return attackModes.filter(x => x.value != AttackMode.Template)
  }
})

const listfileStore = useListfilesStore()
listfileStore.load(true)
const { wordlists, rulefiles } = storeToRefs(listfileStore)

const attackTemplatesStore = useAttackTemplatesStore()
const { templates } = storeToRefs(attackTemplatesStore)

const attackTemplatesToSelect = computed(() =>
  templates.value.map(x => {
    const getIcon = () => {
      if (x.type === AttackTemplateType) {
        return Icons.AttackTemplate
      }
      if (x.type === AttackTemplateSetType) {
        return Icons.AttackTemplateSet
      }
    }

    const getTooltip = () => {
      if (x.type === AttackTemplateType) {
        return 'Attack template'
      }
      if (x.type === AttackTemplateSetType) {
        return 'Template set'
      }
    }

    return {
      text: x.name,
      value: x.id,
      icon: getIcon(),
      iconTooltip: getTooltip()
    }
  })
)

watch(
  () => attackSettings.value.combinatorLeft,
  newLeft => (attackSettings.value.selectedWordlists = [...newLeft, ...attackSettings.value.combinatorRight])
)
watch(
  () => attackSettings.value.combinatorRight,
  newRight => (attackSettings.value.selectedWordlists = [...attackSettings.value.combinatorLeft, ...newRight])
)
</script>

<template v-if="attackSettings.activeStep == StepIndex.Attack">
  <div class="join self-center">
    <input
      type="radio"
      name="options"
      :data-title="attackMode.name"
      class="btn join-item"
      :class="attackMode.value === AttackMode.Template ? '' : 'btn-neutral'"
      :key="attackMode.value"
      :value="attackMode.value"
      v-model="attackSettings.attackMode"
      :aria-label="attackMode.name"
      v-for="attackMode in availableAttackModes"
    />
  </div>

  <div class="my-2"></div>

  <!-- Wordlist -->
  <div v-if="attackSettings.attackMode === AttackMode.Dictionary">
    <WordlistSelect label-text="Select Wordlist" :list="wordlists" v-model="attackSettings.selectedWordlists" :limit="1" />
    <hr class="my-4" />
    <WordlistSelect label-text="Select Rule File(s)" :list="rulefiles" v-model="attackSettings.selectedRulefiles" :limit="Infinity" />
  </div>

  <!-- Combinator -->
  <div v-if="attackSettings.attackMode === AttackMode.Combinator">
    <WordlistSelect label-text="Select Left Wordlist" :list="wordlists" v-model="attackSettings.combinatorLeft" :limit="1" />
    <hr class="my-4" />
    <WordlistSelect label-text="Select Right Wordlist" :list="wordlists" v-model="attackSettings.combinatorRight" :limit="1" />
  </div>

  <!-- Brute-force/Mask -->
  <div v-if="attackSettings.attackMode === AttackMode.Mask">
    <MaskInput v-model="attackSettings.mask" />
    <label class="label cursor-pointer justify-start">
      <input type="checkbox" v-model="attackSettings.maskIncrement" class="checkbox-primary checkbox checkbox-xs" />
      <span><span class="label-text ml-4 font-bold">Mask increment?</span></span>
    </label>
  </div>

  <!-- Wordlist + Mask -->
  <div v-if="attackSettings.attackMode === AttackMode.HybridDM">
    <WordlistSelect label-text="Select Wordlist" :list="wordlists" v-model="attackSettings.selectedWordlists" :limit="1" />
    <hr class="my-4" />
    <MaskInput v-model="attackSettings.mask" />
    <label class="label cursor-pointer justify-start">
      <input type="checkbox" v-model="attackSettings.maskIncrement" class="checkbox-primary checkbox checkbox-xs" />
      <span><span class="label-text ml-4 font-bold">Mask increment?</span></span>
    </label>
  </div>

  <!-- Mask + Wordlist -->
  <div v-if="attackSettings.attackMode === AttackMode.HybridMD">
    <MaskInput v-model="attackSettings.mask" />
    <hr class="my-4" />
    <WordlistSelect label-text="Select Wordlist" :list="wordlists" v-model="attackSettings.selectedWordlists" :limit="1" />
    <label class="label cursor-pointer justify-start">
      <input type="checkbox" v-model="attackSettings.maskIncrement" class="checkbox-primary checkbox checkbox-xs" />
      <span><span class="label-text ml-4 font-bold">Mask increment?</span></span>
    </label>
  </div>

  <div v-if="attackSettings.attackMode === AttackMode.Template">
    <div class="form-control">
      <label class="label font-bold">
        <span class="label-text">Select Template</span>
      </label>
      <SearchableDropdown
        v-model="attackSettings.selectedTemplateId"
        :options="attackTemplatesToSelect"
        placeholderText="Select an attack template..."
      />
    </div>
  </div>

  <hr class="my-4" />

  <label class="label font-bold">Additional Options</label>
  <div>
    <label class="label cursor-pointer justify-start">
      <input type="checkbox" v-model="attackSettings.isDistributed" class="checkbox-primary checkbox checkbox-xs" />
      <span><span class="label-text ml-4 font-bold">Distribute attack?</span></span>
    </label>
    <label class="label cursor-pointer justify-start" v-if="isLoopbackValid(attackSettings)">
      <input type="checkbox" v-model="attackSettings.enableLoopback" class="checkbox-primary checkbox checkbox-xs" />
      <span><span class="label-text ml-4 font-bold">Loopback?</span> (--loopback)</span>
    </label>
    <label class="label cursor-pointer justify-start">
      <input type="checkbox" v-model="attackSettings.optimizedKernels" class="checkbox-primary checkbox checkbox-xs" />
      <span><span class="label-text ml-4 font-bold">Optimized Kernels?</span> (-O)</span>
    </label>
    <label class="label cursor-pointer justify-start">
      <input type="checkbox" v-model="attackSettings.slowCandidates" class="checkbox-primary checkbox checkbox-xs" />
      <span><span class="label-text ml-4 font-bold">Slow Candidates?</span> (-S)</span>
    </label>
  </div>
</template>
