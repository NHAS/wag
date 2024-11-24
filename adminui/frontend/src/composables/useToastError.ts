import { AxiosError } from 'axios'
import { useToast } from 'vue-toastification'

export function useToastError() {
  const toast = useToast()

  const catcher = (e: any, prefixString: string = '', messageProperty: string = 'message') => {
    let errorString = 'Unknown Error'
    if (e instanceof AxiosError) {
      const potentialString = e.response?.data
      if (potentialString == null) {
        errorString = e.message
      } else {
        errorString = potentialString[messageProperty]
      }
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
