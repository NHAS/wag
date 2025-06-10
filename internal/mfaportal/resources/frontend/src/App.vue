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

async function initialRouting() {
  try {
    await nextTick()

    if (info.isDeviceLocked || info.isAccountLocked) {
      console.log("determined locked")
      router.push("/locked")
      notify("VPN Locked", "Your device has been locked. Please contact help")
      return
    }

    if (info.isAuthorised) {
      console.log("determined authed")
      router.push("/success")
      return
    }

    router.push(getMFAPath())

    if (info.availableMfaMethods.length > 0) {
      if (info.isRegistered) {
        notify("VPN Authoirsation Required", "Please reauthenticate with the VPN")
      } else {
        notify("VPN Registration", "Please register an MFA method with the VPN")
      }
    }

  } catch (error) {
    console.error('Navigation error:', error);
  } finally {
    previousState = info.state.userInfo
  }
}

async function stateUpdate() {
  try {
    await nextTick()


    let currentState = info.state.userInfo
    if (currentState == null) {
      return
    }

    if (previousState === null) {
      return
    }

    const isLocked = currentState.account_locked || currentState.device_locked
    if (currentState.account_locked != previousState.account_locked || currentState.device_locked != previousState.device_locked) {
      //if we have become locked
      if (isLocked) {
        notify("VPN Locked", "Your device has been locked. Please contact help")
        router.push("/locked");
        return
      }

      // we have become unlocked
      router.push(getMFAPath())
      return
    }

    const isAuthorised = currentState.is_authorized && currentState.has_registered
    if (currentState.is_authorized != previousState.is_authorized) {
      //we have authorised
      if (isAuthorised) {
        router.push("/success")
        return
      }

      notify("VPN Authorisation Required", "Please authenticate with the VPN")
      // we have had a session expire, or logged out
      router.push(getMFAPath())
      return
    }

    if (currentState.has_registered != previousState.has_registered) {
      router.push(getMFAPath())
      return
    }

    if (router.currentRoute.value.name != null) {

      const currentRouteName = router.currentRoute.value.name.toString()
      const isAuthPage = currentRouteName.includes("auth") || currentRouteName.includes("register")

      if (isAuthPage) {
        const currentMethods = new Map(currentState.available_mfa_methods.map((o) => [o.method, true]));

        // If we are on an mfa method page (registration/authorisation) that has been disabled
        if (!currentMethods.has(currentRouteName.replace("_auth", "").replace("_register", ""))) {
          router.push(getMFAPath())
          return
        }
      }

    }


  } catch (error) {
    console.error('Navigation error:', error);
  } finally {
    previousState = info.state.userInfo
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
