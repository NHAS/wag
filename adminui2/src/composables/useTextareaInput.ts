import { ref, computed } from 'vue'

export function useTextareaInput() {
  const Input = ref('')
  const Arr = computed(() => {

    console.log(Input)
    if(Input === null) {
        return []
    }

    return Input.value
      .trim()
      .split(/\n+/)
      .filter(x => !!x)
      .map(x => x.trim())
  })
  return { Input, Arr }
}