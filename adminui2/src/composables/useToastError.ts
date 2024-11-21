import { AxiosError } from 'axios'
import { useToast } from 'vue-toastification'

export function useToastError() {
  const toast = useToast()

  const catcher = (e: any, prefixString: string = '') => {
    let errorString = 'Unknown Error'
    if (e instanceof AxiosError) {
      errorString = e.response?.data?.message
    } else if (e instanceof Error) {
      errorString = e.message
    }

    console.log(e, typeof e)

    const paddedPrefixString = prefixString.endsWith(' ') ? prefixString : prefixString + ' '

    toast.error(paddedPrefixString + errorString)
  }

  return {
    catcher
  }
}
