import { createRouter, createWebHistory } from "vue-router";

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: "/",
      name: "index",
      component: () => import("../pages/Index.vue"),
    },
    {
      path: "/totp",
      name: "totp",
      component: () => import("../pages/Totp.vue"),
    },
    {
      path: "/pam",
      name: "pam",
      component: () => import("../pages/Pam.vue"),
    },
    {
      path: "/webauthn",
      name: "webauthn",
      component: () => import("../pages/Webauthn.vue"),
    },
    {
      path: "/oidc",
      name: "oidc",
      component: () => import("../pages/Oidc.vue"),
    },
    {
      path: "/success",
      name: "success",
      component: () => import("../pages/Success.vue"),
    },
  ],
});

export default router;
