import { watch, type Ref } from 'vue'
import { ref, computed } from 'vue'

export function usePagination<ItemT>(items: Ref<ItemT[]>, itemsPerPage: number) {
  const activePage = ref(0)
  const totalPages = computed(() => Math.ceil(items.value.length / itemsPerPage))

  const currentItems = computed<ItemT[]>(() => items.value.slice(activePage.value * itemsPerPage, (activePage.value + 1) * itemsPerPage))

  watch(totalPages, newTotalPages => {
    if (newTotalPages == 0) {
      activePage.value = 0
    } else if (activePage.value >= newTotalPages) {
      activePage.value = newTotalPages - 1
    }
  })

  function next() {
    if (activePage.value < totalPages.value - 1) {
      activePage.value++
    }
  }

  function prev() {
    if (activePage.value > 0) {
      activePage.value--
    }
  }

  return {
    next,
    prev,
    activePage,
    totalPages,
    currentItems
  }
}
