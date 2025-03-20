import type { SessionDTO } from './types'

import { client } from '.'

export function getAllSessions(): Promise<SessionDTO[]> {
    return client.get('/api/management/sessions').then(res => {

        if (res.data == null) {
            return []
        }
        return res.data
    })
}