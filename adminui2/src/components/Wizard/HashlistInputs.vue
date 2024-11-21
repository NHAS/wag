<script setup lang="ts">
import { computed, watch } from 'vue'
import { storeToRefs } from 'pinia'

import SearchableDropdown from '@/components/SearchableDropdown.vue'
import HashesInput from '@/components/RulesInput.vue'

import { useWizardHashDetect } from '@/composables/useWizardHashDetect'

import { useTokensStore } from '@/stores/registration_tokens'

const props = defineProps<{
  hashlistName: string
  hashType: string
  hashes: string
  hasUsernames: boolean
  includeSaveButton?: boolean
}>()

const emit = defineEmits(['update:hashlistName', 'update:hashes', 'update:hashType', 'update:hasUsernames', 'savePressed'])

const resourcesStore = useTokensStore()
const { hashTypes: allHashTypes } = storeToRefs(resourcesStore)
resourcesStore.loadHashTypes()

const hashes = computed({
  get: () => props.hashes,
  set: (value: string) => emit('update:hashes', value)
})

const hashlistName = computed({
  get: () => props.hashlistName,
  set: (value: string) => emit('update:hashlistName', value)
})

const hashType = computed({
  get: () => props.hashType,
  set: (value: string) => emit('update:hashType', value)
})

const hasUsernames = computed({
  get: () => props.hasUsernames,
  set: (value: boolean) => emit('update:hasUsernames', value)
})

const hashesArr = computed(() => {
  return hashes.value
    .trim()
    .split(/\n+/)
    .filter(x => !!x)
    .map(x => x.trim())
})

const { detectButtonClass, detectButtonClick, detectButtonText, suggestedHashTypes, isLoadingSuggestions } = useWizardHashDetect(hashesArr)

watch(suggestedHashTypes, newHashTypes => {
  const types = newHashTypes?.possible_types
  if (!types || types.length == 0) {
    return
  }
  hashType.value = types.sort()[0].toString()
})

const filteredHashTypes = computed(() => {
  const suggested = suggestedHashTypes.value?.possible_types
  if (suggested != null) {
    return allHashTypes.value.filter(hashType => suggested.includes(hashType.id))
  }

  return allHashTypes.value
})

const hashTypeOptionsToShow = computed(() =>
  filteredHashTypes.value.map(type => ({
    value: type.id.toString(),
    text: `${type.id} - ${type.name}`
  }))
)
</script>

<template>
  <div class="form-control">
    <label class="label font-bold">
      <span class="label-text">Hashlist Name</span>
    </label>
    <input type="text" placeholder="Dumped Admin NTLM Hashes" v-model="hashlistName" class="input input-bordered w-full max-w-xs" />
  </div>

  <hr class="my-4" />

  <div class="form-control">
    <label class="label font-bold">
      <span class="label-text">Contains Usernames?</span>
    </label>
    <input type="checkbox" v-model="hasUsernames" class="checkbox" />
  </div>

  <div class="form-control mt-2">
    <label class="label font-bold">
      <span class="label-text">Hash Type ({{ filteredHashTypes.length }} options)</span>
    </label>
    <div class="flex justify-between">
      <SearchableDropdown
        class="flex-grow"
        v-model="hashType"
        :options="hashTypeOptionsToShow"
        placeholder-text="Search for a hashtype..."
      />
      <button
        class="btn ml-1"
        :class="detectButtonClass"
        :disabled="isLoadingSuggestions || hashesArr.length == 0"
        @click="detectButtonClick"
      >
        {{ detectButtonText }}
      </button>
    </div>
  </div>

  <label class="label mt-2 font-bold">
    <span class="label-text">Hashes (one per line)</span>
  </label>
  <HashesInput v-model="hashes" />
  <div v-if="props.includeSaveButton" class="mt-4 flex justify-end">
    <button class="btn btn-primary" @click="emit('savePressed')">Save</button>
  </div>
</template>
