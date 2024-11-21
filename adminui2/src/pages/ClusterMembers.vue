<script setup lang="ts">
import { useToast } from 'vue-toastification'
import { useApi } from '@/composables/useApi';
import { getClusterMembers } from '@/api/cluster';
import type { ClusterMember } from '@/api';

import { useAuthStore } from '@/stores/auth'


import { Icons } from '@/util/icons'

const { data: members } = useApi(() => getClusterMembers())

const authStore = useAuthStore()
const toast = useToast()

function nodeName(member: ClusterMember): string {
  let result = member.name
  if (member.name === "") {
    result = "Connecting..."
  }

  if (member.current_node) {
    result += " (current node)"
  }


  return result
}


</script>


<template>
  <main class="w-full p-4">
    <h1 class="text-4xl font-bold">Cluster Members</h1>
    <div class="mt-6 flex flex-wrap gap-6">
      <div class="grid w-full grid-cols-4 gap-4">

        <div v-for="member in members" class="card-compact bg-base-100 shadow-xl min-w-96 max-w-96">
          <div class="card-body">
            <h5 class="card-title overflow-hidden text-ellipsis whitespace-nowrap">{{ nodeName(member) }}</h5>

            <div class="grid grid-cols-2 gap-2">
              <div>ID:</div>
              <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ member.id }}</div>

              <div>Version:</div>
              <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ member.version }}</div>

              <div>Role:</div>
              <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ member.leader ? "Leader" : member.learner ? "Learner" : member.witness ? "Witness" : "Member"  }}</div>

              <div>Status:</div>
              <div class="overflow-hidden text-ellipsis whitespace-nowrap" >{{ member.status }}</div>

              <div>Last Ping:</div>
              <div class="overflow-hidden text-ellipsis whitespace-nowrap">{{ member.last_ping }}</div>

              <div>{{ member.peer_urls?.length > 1 ? "Addresses" : "Address" }}:</div>
              <div class="grid grid-rows-subgrid grid-cols-1">
                <div class="overflow-hidden text-ellipsis whitespace-nowrap" v-for="address in member.peer_urls">{{ address }}</div>
              </div>
            </div>
          </div>
        </div>


      </div>
    </div>
  </main>
</template>

<style scoped>
thead>tr>th {
  background: none !important;
}

.first-col-bold>tr td:first-of-type {
  font-weight: bold;
}
</style>
