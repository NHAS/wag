import type {
  WgDeviceDTO,
  FirewallRulesDTO,
  FirewallTestRequestDTO,
  GenericResponseDTO,
  AclsTestRequestDTO,
  AclsTestResponseDTO
} from './types'

import { client } from '.'

export function getWireguardPeers(): Promise<WgDeviceDTO[]> {
  return client.get('/api/diag/wg').then(res => res.data)
}

export function getFirewallState(): Promise<FirewallRulesDTO> {
  return client.get('/api/diag/firewall').then(res => res.data)
}

export function checkFirewallRule(test: FirewallTestRequestDTO): Promise<GenericResponseDTO> {
  return client.post('/api/diag/check', test).then(res => res.data)
}

export function aclsTest(user: AclsTestRequestDTO): Promise<AclsTestResponseDTO> {
  return client.post('/api/diag/acls', user).then(res => res.data)
}
