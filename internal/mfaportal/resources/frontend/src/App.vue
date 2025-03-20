<script setup lang="ts">
import { RouterView } from "vue-router";

import { useWebSocketStore } from "./store/info";
import { onBeforeMount, onBeforeUnmount, watch, nextTick } from "vue";
import router from "./router";

const info = useWebSocketStore();

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

async function determinePath() {
  try {
    await nextTick()

    if (info.isDeviceLocked || info.isAccountLocked) {
      console.log("detemined locked")
      router.push("/locked")
      notify("VPN Locked", "Your device has been locked. Please contact help")
      return
    }

    if (info.isAuthorised) {
      console.log("detemined authed")
      router.push("/success")
      return
    }

    const path = info.isRegistered ? '/authorise/' : '/register/';

    const methodsHasUserPref = (info.selectedMFAMethod !== "unset" && info.availableMfaMethods.some(x => x.method == info.selectedMFAMethod))
    const methodsHasDefault = (info.defaultMFAMethod != "" && info.availableMfaMethods.some(x => x.method == info.defaultMFAMethod))


    if (info.availableMfaMethods.length == 1) {
      console.log("detemined", path + info.availableMfaMethods[0].method)

      router.push(path + info.availableMfaMethods[0].method)
    } else if (methodsHasDefault || methodsHasUserPref) {


      let mfaMethod = info.selectedMFAMethod
      if(methodsHasDefault) {
        mfaMethod = info.defaultMFAMethod
      }
   
      console.log("detemined", path + mfaMethod)

      router.push(path + mfaMethod)

    } else {
      console.log("detemined selection")
      router.push("/selection")
    }

    if (info.availableMfaMethods.length > 0) {
      if (info.isRegistered) {
        notify("VPN Authoirsation Required", "Please reauthenticate with the VPN")
      } else {
        notify("VPN Registration", "Please register an MFA method with the VPN")
      }
    }

  } catch (error) {
    console.error('Navigation error:', error);
  }
}

// if we've already magically connected 
if (info.isConnected) {
  determinePath()
}

// Set a watch to change the application state on any new updates
watch(info, async newState => {
  if (newState.isConnected) {
    console.log("state changed: ", newState.state)
    determinePath()
  }
})

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
