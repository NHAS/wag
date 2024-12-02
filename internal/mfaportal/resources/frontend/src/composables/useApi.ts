import axios from "axios";
import { reactive, toRefs, type UnwrapRef } from "vue";

import { useToastError } from "@/composables/useToastError";

interface UseAPIState<DTOType> {
  isLoading: boolean;
  data: DTOType | null;
  errorMessage: string | null;
}

interface UseAPIOptions {
  immediate: boolean;
  toastOnError: boolean;
}

const { catcher } = useToastError();

export function useApi<DTOType>(
  apiFunc: () => Promise<DTOType>,
  options: UseAPIOptions = { immediate: true, toastOnError: true },
) {
  const state = reactive<UseAPIState<DTOType>>({
    isLoading: options.immediate,
    data: null,
    errorMessage: null,
  });

  const fetchData = async () => {
    state.isLoading = true;
    state.errorMessage = null;

    try {
      const response = await apiFunc();
      state.data = response as UnwrapRef<DTOType>;
    } catch (err: any) {
      if (axios.isAxiosError(err)) {
        if (options.toastOnError) {
          catcher(err);
        }

        switch (err.response?.status) {
          default:
            state.errorMessage =
              "Something went wrong, status " +
              err.status +
              " " +
              err.response?.data?.message;
            break;
        }
      } else {
        console.warn(err);
        state.errorMessage =
          "Unknown error occured when loading data: " + err?.message;
      }
    } finally {
      state.isLoading = false;
    }
  };

  const silentlyRefresh = async () => {
    try {
      const response = await apiFunc();
      state.data = response as UnwrapRef<DTOType>;
    } catch (err: any) {
      if (axios.isAxiosError(err)) {
        switch (err.response?.status) {
          default:
            state.errorMessage =
              "Something went wrong, status " +
              err.status +
              " " +
              err.response?.data?.message;
            break;
        }
      } else {
        console.warn(err);
        state.errorMessage =
          "Unknown error occured when loading data: " + err?.message;
      }
    }
  };

  if (options.immediate) {
    setTimeout(fetchData, 0);
  }

  return {
    ...toRefs(state),
    fetchData,
    silentlyRefresh,
  };
}
