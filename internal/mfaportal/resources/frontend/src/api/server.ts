import {
    client,
    type StatusDTO,
} from ".";

export function getStatus(): Promise<StatusDTO> {
    return client.get("/api/status").then((res) => {
        return res.data
    }).catch(e => {
        throw e
    });
}

