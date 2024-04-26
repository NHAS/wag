package queue

import (
	"sync"
)

type Queue struct {
	sync.Mutex
	max   int
	items []string
}

func NewQueue(max int) *Queue {
	return &Queue{max: max, items: make([]string, 0, max)}
}

func (q *Queue) Write(line []byte) (int, error) {
	q.Lock()
	defer q.Unlock()

	if len(q.items) < q.max {
		q.items = append([]string{string(line)}, q.items...)
		return len(line), nil
	}

	q.items = q.items[:len(q.items)-1]
	q.items = append([]string{string(line)}, q.items...)
	return len(line), nil
}

func (q *Queue) ReadAll() []string {
	q.Lock()
	defer q.Unlock()

	return q.items
}
