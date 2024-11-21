<script setup lang="ts">
import { computed, ref } from 'vue'
import type { Component } from 'vue'

import AgentConfig from '@/components/Admin/AgentConfig.vue'
import GeneralConfig from '@/components/Admin/GeneralConfig.vue'
import AuthConfig from '@/components/Admin/AuthConfig.vue'

import { Icons } from '@/util/icons'

const tab = (name: string, icon: string, component: Component) => ({ name, icon, component })

const tabs = [tab('General', Icons.Config, GeneralConfig), tab('Auth', Icons.Auth, AuthConfig), tab('Agent', Icons.Agent, AgentConfig)]

const activeTab = ref(0)
const ComponentToRender = computed(() => tabs[activeTab.value].component)
</script>

<template>
  <main class="w-full p-4">
    <h1 class="text-4xl font-bold">Configuration</h1>

    <div class="mt-6 flex flex-wrap gap-6">
      <div class="card min-w-[600px] bg-base-100 shadow-xl">
        <div class="card-body justify-between">
          <div class="tabs tabs-bordered">
            <a class="tab-bordered tab grow">
              <span></span>
            </a>
            <a
              v-for="(tab, i) in tabs"
              :key="i"
              class="tab-bordered tab"
              :class="activeTab == i ? 'tab-active' : ''"
              @click="activeTab = i"
            >
              <span class="mx-2"> <font-awesome-icon :icon="tab.icon" class="mr-2" />{{ tab.name }} </span>
            </a>
            <a class="tab-bordered tab grow">
              <span></span>
            </a>
          </div>

          <ComponentToRender />
        </div>
      </div>
    </div>
  </main>
</template>
