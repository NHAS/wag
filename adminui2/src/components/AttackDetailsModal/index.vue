<script setup lang="ts">
import { computed, ref } from 'vue'

import Overview from '@/components/AttackDetailsModal/Overview.vue'
import Modal from '@/components/Modal.vue'

import {
  JobStatusAwaitingStart,
  JobStatusCreated,
  JobStatusExited,
  JobStatusStarted,
  JobStopReasonFinished,
  JobStopReasonUserStopped
} from '@/api/groups'
import type { AttackWithJobsDTO, JobDTO } from '@/api/types'

import { useAgentsStore } from '@/stores/rules'

const props = defineProps<{
  isOpen: boolean
  attack: AttackWithJobsDTO
}>()

const selectedJobID = ref<string | null>(null)

const emit = defineEmits(['update:isOpen'])

const isOpen = computed({
  get: () => props.isOpen,
  set: (value: boolean) => {
    if (value == false) {
      selectedJobID.value = null
    }

    emit('update:isOpen', value)
  }
})

const agentStore = useAgentsStore()
agentStore.load()
const getAgentName = (id: string) => agentStore.byId(id)?.name ?? 'Unknown'

const selectedJob = computed<JobDTO | null>(() => {
  if (selectedJobID.value == null) {
    return null
  }

  return props.attack.jobs.find(x => x.id == selectedJobID.value) ?? null
})

const logLines = computed<string>(() => {
  if (selectedJob.value == null) {
    return ''
  }

  return (
    '$ ' +
    selectedJob.value.runtime_data.cmd_line +
    '\n\n' +
    selectedJob.value.runtime_data.output_lines.map(x => x.stream).join('\n') +
    (selectedJob.value.runtime_data.error_string != '' ? '\n\n> Error: ' + selectedJob.value.runtime_data.error_string : '')
  )
})
</script>

<template>
  <Modal v-model:isOpen="isOpen">
    <Overview
      :attack="attack"
      v-if="selectedJob == null"
      @selectJob="(jobId: string) => (selectedJobID = jobId)"
      @closed="
        () => {
          isOpen = false
        }
      "
    />
    <div v-else>
      <button class="btn btn-circle btn-ghost btn-sm absolute left-2 top-2 text-xl" @click="() => (selectedJobID = null)">&larr;</button>
      <h2 class="mb-2 text-center text-xl font-bold">
        Job Details
        <div>
          <div
            class="badge badge-success"
            v-if="selectedJob.runtime_data.status == JobStatusExited && selectedJob.runtime_data.stop_reason == JobStopReasonFinished"
          >
            Finished
          </div>
          <div class="badge badge-info" v-else-if="selectedJob.runtime_data.status == JobStatusStarted">Running</div>
          <div
            class="badge badge-secondary"
            v-else-if="selectedJob.runtime_data.status == JobStatusAwaitingStart || selectedJob.runtime_data.status == JobStatusCreated"
          >
            Pending
          </div>
          <div class="badge badge-warning" v-else-if="selectedJob.runtime_data.stop_reason == JobStopReasonUserStopped">Stopped</div>
          <div class="badge badge-error" v-else-if="selectedJob.runtime_data.status == JobStatusExited">
            <span v-if="selectedJob.runtime_data.error_string != ''"
              >Error: <span class="font-mono">{{ selectedJob.runtime_data.error_string }}</span></span
            >
          </div>
          <div class="badge badge-ghost" v-else>Unknown state</div>
        </div>
      </h2>
      <p class="text-center"><strong>Agent: </strong>{{ getAgentName(selectedJob.assigned_agent_id) }}</p>

      <div class="my-8"></div>
      <pre class="log-lines">{{ logLines }}</pre>
    </div>
  </Modal>
</template>

<style scoped>
pre.log-lines {
  background-image: linear-gradient(to bottom, rgba(87, 87, 87, 0.05) 50%, transparent 50%);
  background-repeat: repeat-y;
  border: 1px solid #888;

  background-size: 100% 50px;
  overflow-wrap: break-word;

  line-height: 25px;
  font-size: 15px;

  padding: 0 8px;

  white-space: pre-wrap;
  resize: none;
  min-height: 350px;

  background-attachment: local;
}
</style>
