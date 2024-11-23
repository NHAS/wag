import { ref, computed } from 'vue'

export function useTextareaInput() {
  const Input = ref('')
  const Arr = computed(() => {
    return Input.value
      .trim()
      .split(/\n+/)
      .filter(x => !!x)
      .map(x => x.trim())
  })
  return { Input, Arr }
}
