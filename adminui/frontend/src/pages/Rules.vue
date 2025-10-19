<script setup lang="ts">
import { computed, ref } from 'vue'
import { useToast } from 'vue-toastification'

import Modal from '@/components/Modal.vue'
import PaginationControls from '@/components/PaginationControls.vue'
import PageLoading from '@/components/PageLoading.vue'
import ConfirmModal from '@/components/ConfirmModal.vue'
import EmptyTable from '@/components/EmptyTable.vue'

import { useApi } from '@/composables/useApi'
import { usePagination } from '@/composables/usePagination'
import { useToastError } from '@/composables/useToastError'
import { useTextareaInput } from '@/composables/useTextareaInput'

import { Icons } from '@/util/icons'

import { getAllRules, type RuleDTO, editRule, createRule, deleteRules } from '@/api'

const { data: rulesData, isLoading: isLoadingRules, silentlyRefresh: refreshRules } = useApi(() => getAllRules())

const isLoading = computed(() => {
  return isLoadingRules.value
})

const filterText = ref('')

const allRules = computed(() => rulesData.value ?? [])

const filteredRules = computed(() => {
  const arr = allRules.value

  if (filterText.value == '') {
    return arr
  }

  const searchTerm = filterText.value.trim().toLowerCase()

  return arr.filter(
    x =>
      x.effects.toLowerCase().includes(searchTerm) ||
      x.mfa_routes?.includes(searchTerm) ||
      x.deny_routes?.includes(searchTerm) ||
      x.public_routes?.includes(searchTerm)
  )
})

const { next: nextPage, prev: prevPage, totalPages, currentItems: currentRules, activePage } = usePagination(filteredRules, 20)

const isRuleModalOpen = ref(false)
const ruleModalTitle = ref('')

const toast = useToast()
const { catcher } = useToastError()

const { Input: PublicRules, Arr: PublicRulesArr } = useTextareaInput()
const { Input: MFARules, Arr: MFARulesArr } = useTextareaInput()
const { Input: DenyRules, Arr: DenyRulesArr } = useTextareaInput()

type EffectsType = {
  is_edit: boolean
  effects: string
}

const Effects = ref<EffectsType>({
  is_edit: false,
  effects: ''
})

function openAddRule() {
  ruleModalTitle.value = 'Add Rule'

  PublicRules.value = ''
  MFARules.value = ''
  DenyRules.value = ''
  Effects.value.effects = ''
  Effects.value.is_edit = false

  isRuleModalOpen.value = true
}

function openEditRule(Rule: RuleDTO) {
  ruleModalTitle.value = 'Edit Rule'

  PublicRules.value = Rule.public_routes?.join('\n') ?? ''
  MFARules.value = Rule.mfa_routes?.join('\n') ?? ''
  DenyRules.value = Rule.deny_routes?.join('\n') ?? ''

  Effects.value.effects = Rule.effects
  Effects.value.is_edit = true

  isRuleModalOpen.value = true
}

async function updateRule() {
  try {
    let data: RuleDTO = {
      effects: Effects.value.effects,
      public_routes: PublicRulesArr.value,
      mfa_routes: MFARulesArr.value,
      deny_routes: DenyRulesArr.value
    }

    let resp = null
    if (Effects.value.is_edit) {
      resp = await editRule(data)
    } else {
      resp = await createRule(data)
    }

    refreshRules()

    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      toast.success('rules effecting ' + Effects.value.effects + ' edited!')
      isRuleModalOpen.value = false
    }
  } catch (e) {
    catcher(e, 'failed to apply rule: ')
  }
}

async function tryDeleteRules(rules: string[]) {
  try {
    const resp = await deleteRules(rules)
    refreshRules()
    if (!resp.success) {
      toast.error(resp.message ?? 'Failed')
      return
    } else {
      toast.success('rules ' + rules.join(', ') + ' deleted!')
    }
  } catch (e) {
    catcher(e, 'failed to delete rule: ')
  }
}
</script>

<template>
  <Modal v-model:isOpen="isRuleModalOpen">
    <div class="w-screen max-w-[600px]">
      <h3 class="text-lg font-bold">{{ ruleModalTitle }}</h3>
      <div class="mt-8">
        <p>Make changes to your rule here.</p>

        <div class="form-group">
          <label for="effects" class="block font-medium label-text pt-6">Effects:</label>
          <input
            type="text"
            id="effects"
            class="input input-bordered input-sm w-full"
            required
            v-model="Effects.effects"
            :disabled="Effects.is_edit"
          />
        </div>

        <label for="publicRoutes" class="block font-medium label-text pt-6">Public Routes:</label>
        <textarea class="rules-input textarea textarea-bordered w-full font-mono" rows="3" v-model="PublicRules"></textarea>

        <label for="mfaRoutes" class="block font-medium label-text pt-6">MFA Routes:</label>
        <textarea class="rules-input textarea textarea-bordered w-full font-mono" rows="3" v-model="MFARules"></textarea>

        <label for="denyRoutes" class="block font-medium label-text pt-6">Deny Routes:</label>
        <textarea class="rules-input textarea textarea-bordered w-full font-mono" rows="3" v-model="DenyRules"></textarea>

        <span class="mt-4 flex">
          <button class="btn btn-primary" @click="() => updateRule()">Apply</button>

          <div class="flex flex-grow"></div>

          <button class="btn btn-secondary" @click="() => (isRuleModalOpen = false)">Cancel</button>
        </span>
      </div>
    </div>
  </Modal>

  <main class="w-full p-4">
    <PageLoading v-if="isLoading" />
    <div v-else>
      <h1 class="text-4xl font-bold mb-4">Rules</h1>
      <p>View, create and delete firewall policy rules. If a route is not explicitly allowed, it is blocked.</p>
      <div class="mt-6 flex flex-wrap gap-6">
        <div class="card w-full bg-base-100 shadow-xl min-w-[800px]">
          <div class="card-body">
            <div class="flex flex-row justify-between">
              <div class="tooltip" data-tip="Add rule">
                <button class="btn btn-ghost btn-primary" @click="openAddRule">Add Rule <font-awesome-icon :icon="Icons.Add" /></button>
              </div>
              <div class="form-control">
                <label class="label">
                  <input type="text" class="input input-bordered input-sm" placeholder="Filter..." v-model="filterText" />
                </label>
              </div>
            </div>

            <table class="table table-fixed w-full">
              <thead>
                <tr>
                  <th>Effects</th>
                  <th>Public Rules</th>
                  <th>MFA Rules</th>
                  <th>Deny Rules</th>
                </tr>
              </thead>
              <tbody>
                <tr class="hover group" v-for="rule in currentRules" :key="rule.effects" v-on:dblclick="openEditRule(rule)">
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ rule.effects }}</div>
                  </td>
                  <td class="font-mono">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ rule.public_routes?.join(', ') || '-' }}</div>
                  </td>
                  <td class="font-mono">
                    <p class="overflow-hidden text-ellipsis whitespace-nowrap">{{ rule.mfa_routes?.join(', ') || '-' }}</p>
                  </td>
                  <td class="font-mono relative">
                    <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ rule.deny_routes?.join(', ') || '-' }}</div>
                    <div
                      class="mr-3 absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity duration-200"
                    >
                      <button class="mr-3" @click="openEditRule(rule)">
                        <font-awesome-icon :icon="Icons.Edit" class="text-secondary hover:text-secondary-focus" />
                      </button>
                    </div>
                    <ConfirmModal @on-confirm="() => tryDeleteRules([rule.effects])">
                      <button
                        class="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity duration-200"
                      >
                        <font-awesome-icon :icon="Icons.Delete" class="text-error hover:text-error-focus" />
                      </button>
                    </ConfirmModal>
                  </td>
                </tr>
              </tbody>
            </table>
            <EmptyTable v-if="allRules.length == 0" text="No rules" />
            <EmptyTable v-if="allRules.length != 0 && allRules.length == 0" text="No matching rules" />

            <div class="mt-2 w-full text-center">
              <PaginationControls @next="() => nextPage()" @prev="() => prevPage()" :current-page="activePage" :total-pages="totalPages" />
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>
</template>

<style scoped>
.hashlist-table.table-sm :where(th, td) {
  padding-top: 0.4rem;
  padding-bottom: 0.4rem;
}
</style>
