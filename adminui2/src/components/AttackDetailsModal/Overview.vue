<script setup lang="ts">
import { computed } from 'vue'
import { useToast } from 'vue-toastification'

import TimeSinceDisplay from '@/components/TimeSinceDisplay.vue'
import ConfirmModal from '@/components/ConfirmModal.vue'
import AttackConfigDetails from '@/components/AttackConfigDetails.vue'

import {
  JobStatusAwaitingStart,
  JobStatusCreated,
  JobStatusExited,
  JobStatusStarted,
  JobStopReasonFinished,
  JobStopReasonUserStopped,
  createAttack,
  deleteAttack,
  startAttack,
  stopAttack
} from '@/api/groups'
import type { AttackWithJobsDTO } from '@/api/types'

import { useToastError } from '@/composables/useToastError'

import { useAgentsStore } from '@/stores/rules'

import { getAttackModeName, hashrateStr } from '@/util/hashcat'
import { Icons } from '@/util/icons'
import { timeBetween, timeDurationToReadable } from '@/util/units'

const props = defineProps<{
  attack: AttackWithJobsDTO
}>()

const emit = defineEmits<{
  (e: 'selectJob', jobId: string): void
  (e: 'closed'): void
}>()

const agentStore = useAgentsStore()
agentStore.load()
const getAgentName = (id: string) => agentStore.byId(id)?.name ?? 'Unknown'

const canStop = computed(() => {
  return props.attack.jobs.some(x => x.runtime_data.status == JobStatusStarted || x.runtime_data.status == JobStatusAwaitingStart)
})

const toast = useToast()
const { catcher } = useToastError()

async function start() {
  try {
    await startAttack(props.attack.id)
    toast.success('Started attack')
  } catch (e: any) {
    catcher(e)
  }
}

async function cloneAndStart() {
  try {
    const res = await createAttack({
      hashcat_params: props.attack.hashcat_params,
      hashlist_id: props.attack.hashlist_id,
      is_distributed: props.attack.is_distributed
    })
    toast.success('Created clone of attack')
    await startAttack(res.id)
    toast.success('Started attack')
  } catch (e: any) {
    catcher(e)
  }
}

async function stop() {
  try {
    await stopAttack(props.attack.id)
    toast.success('Requested jobs to be stopped...')
  } catch (e: any) {
    catcher(e)
  }
}

async function onDeleteAttack() {
  try {
    await deleteAttack(props.attack.id)
    emit('closed')
    toast.info('Attack deleted')
  } catch (e: any) {
    catcher(e)
  }
}
</script>

<template>
  <h2 class="mb-8 text-center text-xl font-bold">{{ getAttackModeName(props.attack.hashcat_params.attack_mode) }} Attack</h2>
  <AttackConfigDetails :hashcatParams="attack.hashcat_params"></AttackConfigDetails>
  <div class="my-8"></div>

  <table class="compact-table table w-full" v-if="attack.jobs.length > 0">
    <thead>
      <tr>
        <th>Running Agent</th>
        <th>Status</th>
        <th>Total Hashrate</th>
        <th>Time Started</th>
        <th>Time Remaining</th>
        <th>Time Taken</th>
      </tr>
    </thead>
    <tbody>
      <tr class="cursor-pointer" @click="() => emit('selectJob', job.id)" v-for="job in attack.jobs" :key="job.id">
        <td>
          <strong>{{ getAgentName(job.assigned_agent_id) }}</strong>
        </td>
        <td style="min-width: 130px">
          <div
            class="badge badge-success mr-1"
            v-if="job.runtime_data.status == JobStatusExited && job.runtime_data.stop_reason == JobStopReasonFinished"
          >
            Job finished
          </div>
          <div class="badge badge-info mr-1" v-else-if="job.runtime_data.status == JobStatusStarted">
            {{ job.runtime_data.output_lines.length > 0 ? 'Job running' : 'Hashcat starting...' }}
          </div>
          <div
            class="badge badge-secondary mr-1"
            v-else-if="job.runtime_data.status == JobStatusAwaitingStart || job.runtime_data.status == JobStatusCreated"
          >
            Job pending
          </div>

          <div class="badge badge-warning mr-1" v-else-if="job.runtime_data.stop_reason == JobStopReasonUserStopped">Job stopped</div>
          <div class="badge badge-error mr-1" v-else-if="job.runtime_data.status == JobStatusExited">Job failed</div>

          <div class="badge badge-ghost mr-1" v-else>Unknown state</div>
        </td>
        <td>{{ hashrateStr(job.runtime_summary.hashrate) }}</td>
        <td><TimeSinceDisplay :timestamp="job.runtime_summary.started_time * 1000" /></td>

        <td v-if="job.runtime_summary.estimated_time_remaining > 0">
          {{ timeDurationToReadable(job.runtime_summary.estimated_time_remaining) }}
          left
        </td>
        <td v-else>-</td>

        <td v-if="job.runtime_summary.stopped_time > 0">
          {{ timeBetween(job.runtime_summary.started_time * 1000, job.runtime_summary.stopped_time * 1000) }}
        </td>
        <td v-else>-</td>
      </tr>
    </tbody>
  </table>
  <p v-else>No jobs were found for this attack</p>

  <div class="mt-8 flex flex-row justify-center">
    <div class="join">
      <button @click="() => start()" class="btn join-item btn-sm" v-if="attack.jobs.length == 0">
        <font-awesome-icon :icon="Icons.Start" />
        Start
      </button>

      <button @click="() => cloneAndStart()" class="btn join-item btn-sm" v-else>
        <font-awesome-icon :icon="Icons.Clone" />
        Clone & Start
      </button>

      <button @click="() => stop()" class="btn join-item btn-sm" v-if="canStop">
        <font-awesome-icon :icon="Icons.Stop" />
        Stop
      </button>

      <ConfirmModal @on-confirm="() => onDeleteAttack()" v-else>
        <button class="btn join-item btn-sm">
          <font-awesome-icon :icon="Icons.Delete" />
          Delete
        </button>
      </ConfirmModal>
    </div>
  </div>
</template>
