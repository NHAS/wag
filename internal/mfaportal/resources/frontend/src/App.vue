<script setup lang="ts">
import { RouterView, useRoute } from "vue-router";

import { useWebSocketStore } from "./store/info";
import { onBeforeMount, onBeforeUnmount, watch, nextTick } from "vue";
import router from "./router";
import type { UserInfoDTO } from "./api";


const info = useWebSocketStore();
const route = useRoute();

let previousState: UserInfoDTO | null = null;

onBeforeMount(() => {
  info.connect();
});

onBeforeUnmount(() => {
  info.cleanup();
});


function notify(title: string, message: string) {
  if (!window.Notification) {
    console.log('Browser does not support notifications.');
  } else {

    if (Notification.permission == 'denied') {
      // user doesnt want notifications :(
      return
    }

    // check if permission is already granted
    if (Notification.permission === 'granted') {
      new Notification(title, {
        body: message,
      });
    } else {
      // request permission from user
      Notification.requestPermission().then(function (p) {
        if (p === 'granted') {
          // show notification here
          new Notification(title, {
            body: message,
          });
        } else {
          console.log('User blocked notifications.');
        }
      }).catch(function (err) {
        console.error(err);
      });
    }
  }
}

function getMFAPath(): string {
  const path = info.isRegistered ? '/authorise/' : '/register/';

  const methodsHasUserPref = (info.selectedMFAMethod !== "unset" && info.availableMfaMethods.some(x => x.method == info.selectedMFAMethod))
  const methodsHasDefault = (info.defaultMFAMethod != "" && info.availableMfaMethods.some(x => x.method == info.defaultMFAMethod))

  if(info.isRegistered && !methodsHasUserPref) {
    console.log("determined /error, user mfa method is disabled")
    return "/error?m="+encodeURIComponent("User MFA method has been disabled, contact your administrator") 
  }


  if (info.availableMfaMethods.length == 1) {
    console.log(info.availableMfaMethods.length)
    console.log("determined", path + info.availableMfaMethods[0].method)

    return path + info.availableMfaMethods[0].method
  }


  if (info.isRegistered) {
    console.log("determined user mfa")
    return path + info.selectedMFAMethod
  }

  if (methodsHasDefault) {
    console.log("determined default")
    return path + info.defaultMFAMethod
  }

  console.log("determined selection")
  return "/selection"
}

function isMfaMethodOidc(userMfaMethod: string): boolean {
  return userMfaMethod === "oidc";
}


/*
This function ensures navigation only happens when the router is fully ready,
preventing navigation errors or hangs when pushing routes after async state changes.
Specifically, it fixes the issue where closing and reopening the tab after deauthorizing
would not redirect correctly on reauthorization.
*/
async function safeRouterPush(path: string) {
  await router.isReady();
  await router.push(path).catch((err) => {
    console.error("Error detected when trying to redirect:", err);
  });
}

async function initialRouting() {
  try {
    await nextTick();

    if (info.isDeviceLocked || info.isAccountLocked) {
      console.log("determined locked");
      await safeRouterPush("/locked");
      notify("VPN Locked", "Your device has been locked. Please contact help");
      return;
    }

    if (!info.isRegistered) {
      await safeRouterPush(getMFAPath());
      return;
    } else {
      console.log("Registered checking if it's authorized");
      if (!info.isAuthorised) {
        console.log("not authorised, redirecting to authorise aka connect the tunnel");
        if (isMfaMethodOidc(info.selectedMFAMethod)) {
          await safeRouterPush("/login");
          return;
        }
        await safeRouterPush(getMFAPath());
        return;
      }
      await safeRouterPush("/success");
      return;
    }

    if (info.availableMfaMethods.length > 0) {
      if (info.isRegistered) {
        notify("VPN Authoirsation Required", "Please reauthenticate with the VPN");
      } else {
        notify("VPN Registration", "Please register an MFA method with the VPN");
      }
    }

  } catch (error) {
    console.error('Navigation error:', error);
  } finally {
    previousState = info.state.userInfo;
  }
}


async function stateUpdate() {
  try {
    await nextTick();

    let currentState = info.state.userInfo;
    if (currentState == null) {
      return;
    }

    if (previousState === null) {
      return;
    }

    const isLocked = currentState.account_locked || currentState.device_locked;
    if (currentState.account_locked != previousState.account_locked || currentState.device_locked != previousState.device_locked) {
      console.log("Checking change state lock");
      if (isLocked) {
        notify("VPN Locked", "Your device has been locked. Please contact help");
        await safeRouterPush("/locked");
        return;
      }

      await safeRouterPush(getMFAPath());
      return;
    }

    const isAuthorised = currentState.is_authorized && currentState.has_registered;
    if (currentState.is_authorized != previousState.is_authorized) {
      if (isAuthorised) {
        console.log("Authorized");
        await safeRouterPush("/success");
        return;
      }        
      if (isMfaMethodOidc(currentState.user_mfa_method)) {
        await safeRouterPush("/login");
        return;
      }
      notify("VPN Authorisation Required", "Please authenticate with the VPN");
      await safeRouterPush(getMFAPath());
      return;
    }

    if (currentState.has_registered != previousState.has_registered) {
      await safeRouterPush(getMFAPath());
      return;
    }

    if (router.currentRoute.value.name != null) {
      const currentRouteName = router.currentRoute.value.name.toString();
      const isAuthPage = currentRouteName.includes("auth") || currentRouteName.includes("register");
      if (isAuthPage) {
        const currentMethods = new Map(currentState.available_mfa_methods.map((o) => [o.method, true]));
        if (!currentMethods.has(currentRouteName.replace("_auth", "").replace("_register", ""))) {
          await safeRouterPush(getMFAPath());
          return;
        }
      }
    }
  } catch (error) {
    console.error('Navigation error:', error);
  } finally {
    previousState = info.state.userInfo;
  }
}



if (window.location.pathname !== "/error") {
  // if we've already magically connected 
  if (info.isConnected) {
    initialRouting()
  }

  // Set a watch to change the application state on any new updates
  watch(info, async newState => {
    if (route.path != "/error") {
      if (newState.isConnected) {
        console.log("state update: ", previousState == null, newState.state)
        if (previousState == null) {
          initialRouting()
        } else {
          stateUpdate()
        }
      } else {
        previousState = null
        router.push("/")
      }
    }
  })
}


</script>

<template>
  <main class="w-full min-h-screen">
    <div class="bg-slate-200 min-h-screen flex items-center justify-center p-4">
      <div class="card bg-neutral shadow-xl max-w-3xl h-max text-neutral-content">
        <div class="card-body">
          <RouterView />
        </div>
      </div>
    </div>
  </main>
</template>
