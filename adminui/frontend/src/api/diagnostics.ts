import type {
  WgDeviceDTO,
  FirewallRulesDTO,
  FirewallTestRequestDTO,
  GenericResponseDTO,
  AclsTestRequestDTO,
  AclsTestResponseDTO,
  TestNotificationsRequestDTO
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

export function getUserAcls(user: AclsTestRequestDTO): Promise<AclsTestResponseDTO> {
  return client.post('/api/diag/acls', user).then(res => res.data)
}


export function testNotifications(dummyNotification: TestNotificationsRequestDTO): Promise<GenericResponseDTO> {
  return client.post('/api/diag/notifications', dummyNotification).then(res => res.data)
}

