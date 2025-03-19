import { defineStore } from "pinia";
import { ref, computed } from "vue";
import type { AuthorisationResponseDTO, ChallengeAuthorisationRequestDTO, UserInfoDTO } from "@/api/types";
import { useToast } from "vue-toastification";
const toast = useToast();
export interface WebSocketState {
  connection: WebSocket | null;
  isConnected: boolean;
  isConnecting: boolean;
  isClosed: boolean;
  reconnectAttempts: number;
  userInfo: UserInfoDTO | null;
  connectionError: string | null;
  challenge: string | null;
}

export const useWebSocketStore = defineStore("websocket", () => {
  // State
  const state = ref<WebSocketState>({
    connection: null,
    isConnected: false,
    isConnecting: false,
    isClosed: false,
    reconnectAttempts: 0,

    userInfo: null,
    connectionError: null,

    challenge: null
  });

  // Maximum reconnection attempts
  const MAX_RECONNECT_ATTEMPTS = 5;
  const LOCAL_STORAGE_KEY = "wag-challenge-key";

  // Connect to WebSocket
  const connect = () => {
    if (state.value.isConnected || state.value.isConnecting || state.value.isClosed) {
      return;
    }

    state.value.challenge = localStorage.getItem(LOCAL_STORAGE_KEY)

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

      console.log("got object", data)

      switch (data.type) {
        case "info":
          if(state.value.userInfo !== null) {
            state.value.userInfo = data;
          }
          break
        case "endpoint-change-challenge":
          sendChallenge()
          break;
        case "ping":
          state.value.connection?.send(JSON.stringify({
            "type": "pong",
            "pong": true
          }))
          console.log("got ping")
          break;

        case "authorised":
          const authorisationMessage = data as AuthorisationResponseDTO
          state.value.challenge = authorisationMessage.challenge
          localStorage.setItem(LOCAL_STORAGE_KEY, authorisationMessage.challenge)
          state.value.userInfo = authorisationMessage.info

          console.log("got authorised message: ", data)
          break
        default:
          console.log("Server sent message with unknown type: ", data.type, data)
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

    if(state.value.isClosed) {
      return
    }

    
    toast.error("Connection lost attempting to reconnect...")
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
  const sendChallenge = () => {
    if (!state.value.isConnected || !state.value.connection) {
      console.error("Cannot send challenge: WebSocket not connected");
      return;
    }

    const challengeData: ChallengeAuthorisationRequestDTO = {
      type: "challenge-response" ,
      challenge: state.value.challenge?? ""
    };
    state.value.connection.send(JSON.stringify(challengeData));
  };

  // Disconnect WebSocket
  const disconnect = () => {
    state.value.isClosed = true
    state.value.isConnected = false;

    if (state.value.connection) {
      state.value.connection.close(1000, "Client disconnecting");
      state.value.connection = null;
    }
  };


  // Computed properties for easy access to user info
  const isLoggedIn = computed(() => state.value.userInfo?.is_authorized ?? false);
  const username = computed(() => state.value.userInfo?.username ?? "");
  const selectedMFAMethod = computed(() => state.value.userInfo?.user_mfa_method ?? "unset");
  const availableMfaMethods = computed(() => state.value.userInfo?.available_mfa_methods ?? []);
  const defaultMFAMethod = computed(() => state.value.userInfo?.default_mfa ?? "");
  const isAccountLocked = computed(() => state.value.userInfo?.account_locked ?? false);
  const isDeviceLocked = computed(() => state.value.userInfo?.device_locked ?? false); 
  const isAuthorised = computed(() => state.value.userInfo?.is_authorized ?? false);
  const isRegistered = computed(() => state.value.userInfo?.has_registered ?? false);
  const isConnected = computed(() => state.value.isConnected);
  const helpMail = computed(() => state.value.userInfo?.helpmail ?? "");

  // Cleanup on unmount
  const cleanup = () => {
    disconnect();
  };

  return {
    state,
    connect,
    disconnect,
    isConnected,
    isLoggedIn,
    username,
    selectedMFAMethod,
    availableMfaMethods,
    defaultMFAMethod,
    isDeviceLocked,
    isAccountLocked,
    isAuthorised,
    isRegistered,
    helpMail,
    cleanup
  };
});