import { defineStore } from "pinia";
import { ref, computed } from "vue";
import type { ChallengeAuthorisationDTO, UserInfoDTO } from "@/api/types";

export interface WebSocketState {
  connection: WebSocket | null;
  isConnected: boolean;
  isConnecting: boolean;
  reconnectAttempts: number;
  userInfo: UserInfoDTO | null;
  connectionError: string | null;
  lastPingTime: number | null;
}

export const useWebSocketStore = defineStore("websocket", () => {
  // State
  const state = ref<WebSocketState>({
    connection: null,
    isConnected: false,
    isConnecting: false,
    reconnectAttempts: 0,
    userInfo: null,
    connectionError: null,
    lastPingTime: null
  });

  // Maximum reconnection attempts
  const MAX_RECONNECT_ATTEMPTS = 5;

  // Connect to WebSocket
  const connect = () => {
    if (state.value.isConnected || state.value.isConnecting) {
      return;
    }

    state.value.isConnecting = true;
    state.value.connectionError = null;

    try {
      // Get the WebSocket URL from environment or configuration
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${wsProtocol}//${window.location.host}/api/session`;

      const ws = new WebSocket(wsUrl);

      ws.onopen = handleOpen;
      ws.onmessage = handleMessage;
      ws.onerror = handleError;
      ws.onclose = handleClose;

      state.value.connection = ws;
    } catch (error) {
      handleError(error as Event);
    }
  };

  // Handle WebSocket open event
  const handleOpen = () => {
    console.log("WebSocket connection established");
    state.value.isConnected = true;
    state.value.isConnecting = false;
    state.value.reconnectAttempts = 0;
  };

  // Handle WebSocket messages
  const handleMessage = (event: MessageEvent) => {
    try {
      const data = JSON.parse(event.data);

      if (data.type === undefined) {
        console.log("Server sent unknown object: ", data)
        return
      }

      switch (data.type) {
        case "info":
          state.value.userInfo = data;
          break;
        case "deauthed":
            if( state.value.userInfo !== null) {
              // we are no longer authed, and there is no challenge to sent to auto re-auth, so make the user reauth
              state.value.userInfo.is_authorized = false
            }
          break
        case "endpoint-change-challenge":
          if( state.value.userInfo !== null) {
            // we are no longer authed, and there is no challenge to sent to auto re-auth, so make the user reauth
            state.value.userInfo.is_authorized = false
          }
          break;
        default:
          console.log("Server sent message with unknown type: ", data.type)
      }
      // Check if the message is UserInfoDTO
      if (data.username !== undefined) {
      }

      // Additional message handling can be added here
    } catch (error) {
      console.error("Error parsing WebSocket message:", error);
    }
  };

  // Handle WebSocket errors
  const handleError = (event: Event) => {
    console.error("WebSocket error:", event);
    state.value.connectionError = "Connection error occurred";
    state.value.isConnecting = false;
  };

  // Handle WebSocket close event
  const handleClose = (event: CloseEvent) => {
    console.log("WebSocket connection closed:", event);
    state.value.isConnected = false;
    state.value.isConnecting = false;

    // Attempt to reconnect if not a normal closure
    if (event.code !== 1000 && state.value.reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
      const delay = Math.min(1000 * (state.value.reconnectAttempts + 1), 10000);
      state.value.reconnectAttempts++;

      setTimeout(() => {
        console.log(`Attempting to reconnect (${state.value.reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`);
        connect();
      }, delay);
    }
  };

  // Send a challenge to the server
  const sendChallenge = (challenge: string) => {
    if (!state.value.isConnected || !state.value.connection) {
      console.error("Cannot send challenge: WebSocket not connected");
      return;
    }

    const challengeData: ChallengeAuthorisationDTO = { challenge };
    state.value.connection.send(JSON.stringify(challengeData));
  };

  // Disconnect WebSocket
  const disconnect = () => {
    if (state.value.connection) {
      state.value.connection.close(1000, "Client disconnecting");
      state.value.connection = null;
      state.value.isConnected = false;
    }
  };


  // Computed properties for easy access to user info
  const isLoggedIn = computed(() => state.value.userInfo?.is_authorized ?? false);
  const username = computed(() => state.value.userInfo?.username ?? "");
  const availableMfaMethods = computed(() => state.value.userInfo?.available_mfa_methods ?? []);
  const defaultMFAMethod = computed(() => state.value.userInfo?.default_mfa ?? "");
  const isLocked = computed(() => state.value.userInfo?.is_locked ?? false);
  const isRegistered = computed(() => state.value.userInfo?.has_registered ?? false);
  const helpMail = computed(() => state.value.userInfo?.helpmail ?? "");
  const isLoading = computed(() => !state.value.isConnected)

  // Cleanup on unmount
  const cleanup = () => {
    disconnect();
  };

  return {
    state,
    connect,
    disconnect,
    sendChallenge,
    isLoading,
    isLoggedIn,
    username,
    availableMfaMethods,
    defaultMFAMethod,
    isLocked,
    isRegistered,
    helpMail,
    cleanup
  };
});