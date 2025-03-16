import { createApp, onMounted, onBeforeUnmount, onBeforeMount } from "vue";
import { createPinia } from "pinia";
import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";
import { fas } from "@fortawesome/free-solid-svg-icons";
import { library } from "@fortawesome/fontawesome-svg-core";
import Toast, { useToast } from "vue-toastification";

import "vue-toastification/dist/index.css";
import "./styles.css";

import App from "./App.vue";
import router from "./router";

const app = createApp(App);

library.add(fas);

app.component("font-awesome-icon", FontAwesomeIcon);
app.use(createPinia());
app.use(Toast, {});
app.use(router);


const toast = useToast();
app.config.errorHandler = (err) => {
  if (err instanceof Error) {
    toast.error("Unexpected frontend error:\n\n" + err.message);
  } else if (err?.toString != null) {
    toast.error("Unexpected frontend error:\n\n" + err.toString());
  } else {
    toast.error("Unexpected frontend error. Check console for details.");
  }
  console.error(err);
};

app.mount("#app");
