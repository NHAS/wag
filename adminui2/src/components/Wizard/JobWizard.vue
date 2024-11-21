<script setup lang="ts">
import { computed, watch, reactive } from 'vue'
import { storeToRefs } from 'pinia'
import { useToast } from 'vue-toastification'

import HashlistInputs from '@/components/Wizard/HashlistInputs.vue'
import AttackSettings from '@/components/Wizard/AttackSettings.vue'
import AttackConfigDetails from '@/components/AttackConfigDetails.vue'
import SearchableDropdown from '@/components/SearchableDropdown.vue'
import HrOr from '@/components/HrOr.vue'

import { createHashlist, createProject, createAttack, startAttack, getProject, getHashlist } from '@/api/groups'
import type { AttackDTO, HashlistCreateResponseDTO, ProjectDTO } from '@/api/types'
import { AttackTemplateSetType, AttackTemplateType } from '@/api/attackTemplate'

import { useToastError } from '@/composables/useToastError'
import { useAttackSettings } from '@/composables/useAttackSettings'

import { useTokensStore } from '@/stores/registration_tokens'
import { useProjectsStore } from '@/stores/groups'
import { useAttackTemplatesStore } from '@/stores/attackTemplates'

import { AttackMode, makeHashcatParams } from '@/util/hashcat'

/*
 * Props
 */
const props = withDefaults(
  defineProps<{
    // Set to 0 for full wizard, 1 if project is already made, 2 if hashlist is already made...
    firstStep?: number
    existingProjectId?: string
    existingHashlistId?: string
  }>(),
  {
    firstStep: 0
  }
)

interface StartEmitDetails {
  projectId: string
  hashlistId: string
  attackId: string
}

const emit = defineEmits<{
  (e: 'successfulStart', details: StartEmitDetails): void
  (e: 'createdHashlist'): void
  (e: 'createdAttack'): void
}>()

const projectsStore = useProjectsStore()
const { projects } = storeToRefs(projectsStore)
projectsStore.load(true)

const resourcesStore = useTokensStore()
const { hashTypes: allHashTypes } = storeToRefs(resourcesStore)
resourcesStore.loadHashTypes()

const projectSelectOptions = computed(() => [
  { value: '', text: 'Create new project 🖋' },
  ...projects.value.map(project => ({
    value: project.id,
    text: project.name
  }))
])

const steps = [
  { name: 'Choose or Create Project' },
  { name: 'Add Hashlist' },
  { name: 'Configure Attack Settings' },
  { name: 'Review & Start Attack' }
]

enum StepIndex {
  Project = 0,
  Hashlist = 1,
  Attack = 2,
  Review = 3
}

const stepsToDisplay = steps.slice(props.firstStep)

/*
 * User Inputs
 */
const inputs = reactive({
  projectName: '',
  selectedProjectId: props.existingProjectId ?? '',

  hashlistName: '',
  selectedHashlistId: props.existingHashlistId ?? '',
  hashType: '0',
  hashes: '',
  hasUsernames: false,

  activeStep: props.firstStep
})

const { attackSettings, validationError: attackSettingsValidationError } = useAttackSettings()
const attackTemplateStore = useAttackTemplatesStore()

// If a user starts typing in a new project name, then de-select existing project
watch(
  () => inputs.projectName,
  newProjName => {
    if (newProjName != '') {
      inputs.selectedProjectId = ''
    }
  }
)

// If a user selects an existing project, remove the project name they've typed
watch(
  () => inputs.selectedProjectId,
  newSelectedProj => {
    if (newSelectedProj != '') {
      inputs.projectName = ''
    }
  }
)

const hashesArr = computed(() => {
  return inputs.hashes
    .trim()
    .split(/\n+/)
    .filter(x => !!x)
    .map(x => x.trim())
})

const selectedHashType = computed(() => allHashTypes.value.find(x => x.id.toString() === inputs.hashType))

/*
 * Step validations
 */
const projectStepValidationError = computed(() => {
  if (inputs.projectName == '' && inputs.selectedProjectId == '') {
    return 'Please select an existing project or input a new project name'
  }
  if (inputs.projectName.length < 3 && inputs.selectedProjectId == '') {
    return 'Project name too short (3 min)'
  }
  return null
})

const hashlistStepValidationError = computed(() => {
  if (inputs.hashlistName == '') {
    return 'Please name the hashlist'
  }
  if (inputs.hashlistName.length < 3) {
    return 'Hashlist name too short (3 min)'
  }

  if (hashesArr.value.length == 0) {
    return 'Please input at least one hash'
  }
  return null
})

const toast = useToast()
const { catcher } = useToastError()

/*
 * API Helpers
 */
async function saveOrGetProject(): Promise<ProjectDTO> {
  try {
    if (inputs.selectedProjectId) {
      const proj = await getProject(inputs.selectedProjectId)
      return proj
    }

    const proj = await createProject(inputs.projectName, '')

    inputs.selectedProjectId = proj.id

    toast.success(`Created project "${inputs.projectName}"!`)
    return proj
  } catch (err: any) {
    catcher(err, 'Failed to create project. ')
    // Throw up so our caller knows an error happened
    throw err
  } finally {
    projectsStore.load(true)
  }
}

async function saveOrGetHashlist(): Promise<HashlistCreateResponseDTO> {
  const proj = await saveOrGetProject()

  try {
    if (inputs.selectedHashlistId) {
      const hashlist = await getHashlist(inputs.selectedHashlistId)
      return {
        id: hashlist.id,
        num_populated_from_potfile: 0
      }
    }

    const hashlist = await createHashlist({
      project_id: proj.id,
      name: inputs.hashlistName,
      hash_type: Number(inputs.hashType),
      input_hashes: hashesArr.value,
      has_usernames: inputs.hasUsernames
    })

    emit('createdHashlist')

    toast.success(`Created hashlist "${inputs.hashlistName}"!`)

    inputs.selectedHashlistId = hashlist.id

    return hashlist
  } catch (err: any) {
    catcher(err, 'Failed to create hashlist. ')
    throw err
  }
}

const computedHashcatParams = computed(() => {
  return makeHashcatParams(Number(inputs.hashType), attackSettings)
})

async function saveUptoAttack(): Promise<AttackDTO[]> {
  const hashlist = await saveOrGetHashlist()

  const saveAttackFromTemplate = async () => {
    const tmpl = attackTemplateStore.byId(attackSettings.selectedTemplateId)

    if (tmpl == null) {
      throw new Error('Template was null')
    }

    if (tmpl.type === AttackTemplateType) {
      if (tmpl.hashcat_params == null) {
        throw new Error('Template settings were null')
      }

      const attack = await createAttack({
        hashlist_id: hashlist.id,
        hashcat_params: tmpl.hashcat_params,
        is_distributed: attackSettings.isDistributed
      })

      return [attack]
    } else if (tmpl.type === AttackTemplateSetType) {
      const attacks = []

      if (tmpl.attack_template_ids == null || tmpl.attack_template_ids.length == 0) {
        throw new Error('Template settings were null')
      }

      for (const tmplId of tmpl.attack_template_ids) {
        const subTmpl = attackTemplateStore.byId(tmplId)
        if (subTmpl == null || subTmpl.hashcat_params == null) {
          throw new Error('Template settings were null')
        }

        const attack = await createAttack({
          hashlist_id: hashlist.id,
          hashcat_params: subTmpl.hashcat_params,
          is_distributed: attackSettings.isDistributed
        })
        attacks.push(attack)
      }

      return attacks
    } else {
      throw new Error(`Unknown attack templaet type ${tmpl.type}`)
    }
  }

  const saveAttack = async () => {
    const attack = await createAttack({
      hashlist_id: hashlist.id,
      hashcat_params: computedHashcatParams.value,
      is_distributed: attackSettings.isDistributed
    })
    toast.success('Created attack!')
    return [attack]
  }

  try {
    if (attackSettings.attackMode === AttackMode.Template) {
      const res = await saveAttackFromTemplate()
      emit('createdAttack')
      return res
    }

    const res = await saveAttack()
    emit('createdAttack')
    return res
  } catch (err: any) {
    catcher(err, 'Failed to create attack. ')
    throw err
  }
}

async function saveAndStartAttack() {
  const attacks = await saveUptoAttack()

  for (const attack of attacks) {
    try {
      await startAttack(attack.id)
      emit('successfulStart', {
        projectId: inputs.selectedProjectId,
        hashlistId: inputs.selectedHashlistId,
        attackId: attack.id
      })
    } catch (err: any) {
      catcher(err, `Failed to start attack ${attack.id}. `)
    }
  }

  toast.success(`Started attack${attacks.length === 1 ? '' : 's'}!`)
}

// Most of the action functions bubble errors in here, but emit UI warnings
// So, this is to help that
function callBubblewrapped(fn: () => Promise<any>) {
  fn().catch(() => null)
}
</script>

<template>
  <div class="mt-6 flex flex-col flex-wrap gap-6">
    <ul class="steps my-1">
      <li
        v-for="(step, index) in stepsToDisplay"
        :key="index"
        :class="index + props.firstStep <= inputs.activeStep ? 'step step-primary' : 'step'"
      >
        {{ step.name }}
      </li>
    </ul>
    <div class="card min-w-max self-center bg-base-100 shadow-xl" style="min-width: 800px">
      <div class="card-body">
        <h2 class="card-title mb-4 w-96 justify-center self-center text-center">
          Step {{ inputs.activeStep + 1 - props.firstStep }}. {{ steps[inputs.activeStep].name }}
          <span v-if="inputs.activeStep == StepIndex.Attack"> </span>
        </h2>

        <!-- Create/Select Project -->
        <template v-if="inputs.activeStep == StepIndex.Project">
          <div class="form-control">
            <label class="label font-bold">
              <span class="label-text">Choose Project</span>
            </label>
            <SearchableDropdown
              v-model="inputs.selectedProjectId"
              :options="projectSelectOptions"
              placeholderText="Select existing project..."
              class="max-w-xs"
            />

            <HrOr class="my-4 text-xl" />

            <label class="label font-bold">
              <span class="label-text">New Project Name</span>
            </label>
            <input v-model="inputs.projectName" type="text" placeholder="12345 Example Corp" class="input input-bordered w-full max-w-xs" />

            <div class="mt-8 flex justify-between">
              <div class="flex justify-start">
                <button class="link" @click="() => callBubblewrapped(saveOrGetProject)" v-if="projectStepValidationError == null">
                  Create empty project and finish
                </button>
              </div>
              <div class="card-actions justify-end">
                <div class="tooltip" :data-tip="projectStepValidationError">
                  <button class="btn btn-primary" @click="inputs.activeStep++" :disabled="projectStepValidationError != null">Next</button>
                </div>
              </div>
            </div>
          </div>
        </template>

        <!-- Create Hashlist -->
        <template v-if="inputs.activeStep == StepIndex.Hashlist">
          <div class="form-control">
            <HashlistInputs
              v-model:hasUsernames="inputs.hasUsernames"
              v-model:hashes="inputs.hashes"
              v-model:hashType="inputs.hashType"
              v-model:hashlistName="inputs.hashlistName"
            />

            <div class="mt-8 flex justify-between">
              <div class="flex justify-start">
                <button class="link" @click="() => callBubblewrapped(saveOrGetHashlist)" v-if="hashlistStepValidationError == null">
                  Save hashlist and finish
                </button>
              </div>
              <div class="card-actions justify-end">
                <button class="btn btn-ghost" @click="inputs.activeStep--">Previous</button>
                <div class="tooltip" :data-tip="hashlistStepValidationError">
                  <button class="btn btn-primary" @click="inputs.activeStep++" :disabled="hashlistStepValidationError != null">Next</button>
                </div>
              </div>
            </div>
          </div>
        </template>

        <!-- Attack settings -->
        <template v-if="inputs.activeStep == StepIndex.Attack">
          <AttackSettings v-model="attackSettings" enableTemplate />

          <div class="mt-8 flex justify-between">
            <div class="flex justify-start">
              <button class="link" @click="() => callBubblewrapped(saveUptoAttack)" v-if="attackSettingsValidationError == null">
                Save attack and finish
              </button>
            </div>

            <div class="card-actions justify-end">
              <button class="btn btn-ghost" @click="inputs.activeStep--">Previous</button>

              <div class="tooltip" :data-tip="attackSettingsValidationError">
                <button class="btn btn-primary" @click="inputs.activeStep++" :disabled="attackSettingsValidationError != null">Next</button>
              </div>
            </div>
          </div>
        </template>

        <!-- Review/start -->
        <template v-if="inputs.activeStep == StepIndex.Review">
          <div v-if="props.firstStep == 0" class="mt-6">
            <h3 class="text-lg font-bold">Project Settings</h3>
            <table class="compact-table table w-full">
              <thead>
                <tr>
                  <th class="w-1/2">Option</th>
                  <th class="w-1/2">Value</th>
                </tr>
              </thead>
              <tbody>
                <tr v-if="inputs.selectedProjectId != ''">
                  <td><strong>Existing Project</strong></td>
                  <td>{{ projectsStore.byId(inputs.selectedProjectId)?.name ?? 'Unknown' }}</td>
                </tr>
                <tr v-else>
                  <td><strong>Project Name</strong></td>
                  <td>{{ inputs.projectName }}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div v-if="props.firstStep <= 1" class="mt-6">
            <h3 class="text-lg font-bold">Hashlist Settings</h3>
            <table class="compact-table table w-full">
              <thead>
                <tr>
                  <th class="w-1/2">Option</th>
                  <th class="w-1/2">Value</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><strong>Hashlist Name</strong></td>
                  <td>{{ inputs.hashlistName }}</td>
                </tr>
                <tr>
                  <td><strong>Hashlist Type</strong></td>
                  <td>{{ selectedHashType?.id }} - {{ selectedHashType?.name }}</td>
                </tr>
                <tr>
                  <td><strong>Number of Hashes</strong></td>
                  <td>{{ hashesArr.length }}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div class="mt-6">
            <h3 class="text-lg font-bold">Attack Settings</h3>
            <AttackConfigDetails
              :hashcatParams="computedHashcatParams"
              :is-distributed="attackSettings.isDistributed"
            ></AttackConfigDetails>
          </div>

          <div class="mt-8 flex justify-between">
            <div class="flex justify-start">
              <button class="link" @click="() => callBubblewrapped(saveUptoAttack)">Save attack and finish</button>
            </div>

            <div class="card-actions justify-end">
              <button class="btn btn-ghost" @click="inputs.activeStep--">Previous</button>
              <button class="btn btn-success" @click="saveAndStartAttack">Start Attack</button>
            </div>
          </div>
        </template>
      </div>
    </div>
  </div>
</template>

<style scoped>
table.first-col-bold tr > td:first-of-type {
  font-weight: bold;
}
</style>
