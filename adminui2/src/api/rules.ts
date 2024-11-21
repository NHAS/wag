import type { GenericResponseDTO, RuleDTO } from './types'

import { client } from '.'

export function getAllRules(): Promise<RuleDTO[]> {
  return client.get('/api/policy/rules').then(res => res.data)
}

export function editRule(updatedRule: RuleDTO): Promise<GenericResponseDTO> {
  return client.put('/api/policy/rules', updatedRule).then(res => res.data)
}

export function createRule(rule: RuleDTO): Promise<GenericResponseDTO> {
  return client.post('/api/policy/rules', rule).then(res => res.data)
}
