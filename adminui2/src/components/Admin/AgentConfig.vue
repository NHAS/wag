<script setup lang="ts">
import { reactive, watch } from 'vue'
import { useToast } from 'vue-toastification'
import { storeToRefs } from 'pinia'

import { useToastError } from '@/composables/useToastError'

import { useConfigStore } from '@/stores/config'
import { useAdminConfigStore } from '@/stores/adminConfig'

const configStore = useConfigStore()
const adminConfigStore = useAdminConfigStore()
const { config: adminConfig } = storeToRefs(adminConfigStore)
adminConfigStore.load()

const agentSettings = reactive({
  auto_sync_listfiles: adminConfig.value?.agent?.auto_sync_listfiles ?? true,
  split_jobs_per_agent: adminConfig.value?.agent?.split_jobs_per_agent ?? 1
})

watch(adminConfig, newSettings => {
  const agent = newSettings?.agent
  if (agent == null) {
    return
  }

  agentSettings.auto_sync_listfiles = agent.auto_sync_listfiles
  agentSettings.split_jobs_per_agent = agent.split_jobs_per_agent
})

const toast = useToast()
const { catcher } = useToastError()

async function onSave() {
  try {
    await adminConfigStore.update({
      agent: {
        auto_sync_listfiles: agentSettings.auto_sync_listfiles,
        split_jobs_per_agent: agentSettings.split_jobs_per_agent
      }
    })
    configStore.load()
    toast.success('Settings saved')
  } catch (e: any) {
    catcher(e)
  } finally {
    adminConfigStore.load()
  }
}
</script>

<template>
  <table class="compact-table table-first-col-bold table">
    <thead>
      <tr>
        <th>Setting</th>
        <th>Value</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>Automatically sync list files to agents</td>
        <td><input type="checkbox" class="toggle" v-model="agentSettings.auto_sync_listfiles" /></td>
      </tr>

      <tr>
        <td>Number of jobs per agent for each attack (recommended: 1)</td>
        <td><input type="number" v-model.number="agentSettings.split_jobs_per_agent" class="input input-bordered input-sm w-40" /></td>
      </tr>

      <tr>
        <td></td>
        <td>
          <button class="btn btn-primary btn-sm" @click="() => onSave()">Save</button>
        </td>
      </tr>
    </tbody>
  </table>
</template>
