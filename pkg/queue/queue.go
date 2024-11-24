package queue

import (
	"sync"
)

type Queue[T any] struct {
	sync.Mutex
	max   int
	items []T
}

func NewQueue[T any](max int) *Queue[T] {
	return &Queue[T]{
		max:   max,
		items: make([]T, 0, max),
	}
}

func (q *Queue[T]) Write(item T) (int, error) {
	q.Lock()
	defer q.Unlock()

	if len(q.items) < q.max {
		q.items = append([]T{item}, q.items...)
		return 1, nil
	}

	q.items = q.items[:len(q.items)-1]
	q.items = append([]T{item}, q.items...)
	return 1, nil
}

func (q *Queue[T]) ReadAll() []T {
	q.Lock()
	defer q.Unlock()
	return q.items
}
