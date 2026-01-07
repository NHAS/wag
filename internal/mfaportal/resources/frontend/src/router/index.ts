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
      path: "/selection",
      name: "selection",
      component: () => import("../pages/Selection.vue"),
    },
    {
      path: "/register/totp",
      name: "totp_register",
      component: () => import("../pages/registration/Totp.vue"),
    },
    {
      path: "/authorise/totp",
      name: "totp_auth",
      component: () => import("../pages/authorisation/Totp.vue"),
    },
    {
      path: "/register/pam",
      name: "pam_register",
      component: () => import("../pages/registration/Pam.vue"),
    },
    {
      path: "/authorise/pam",
      name: "pam_authorise",
      component: () => import("../pages/authorisation/Pam.vue"),
    },
    {
      path: "/register/webauthn",
      name: "webauthn_register",
      component: () => import("../pages/registration/Webauthn.vue"),
    },
    {
      path: "/authorise/webauthn",
      name: "webauthn_auth",
      component: () => import("../pages/authorisation/Webauthn.vue"),
    },
    {
      path: "/register/oidc",
      name: "oidc_register",
      component: () => import("../pages/Oidc.vue"),
    },
    {
      path: "/authorise/oidc",
      name: "oidc_auth",
      component: () => import("../pages/Oidc.vue"),
    },
    {
      path: "/success",
      name: "success",
      component: () => import("../pages/Success.vue"),
    },
    {
      path: "/error",
      name: "error",
      component: () => import("../pages/Error.vue"),
    },
    {
      path: "/locked",
      name: "locked",
      component: () => import("../pages/Locked.vue"),
    },
  ],
});

export default router;
