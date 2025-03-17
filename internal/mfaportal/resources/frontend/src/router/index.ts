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
    },    {
      path: "/register/pam",
      name: "pam_register",
      component: () => import("../pages/registration/Pam.vue"),
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
      path: "/oidc",
      name: "oidc",
      component: () => import("../pages/Oidc.vue"),
    },
    {
      path: "/success",
      name: "success",
      component: () => import("../pages/Success.vue"),
    }
  ],
});

export default router;
