package authentication

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type dummyCtx struct {
	subject string
}

func (d *dummyCtx) IsAuthenticated() bool {
	return d.subject != ""
}

func TestInMemorySessions_SetAndGet(t *testing.T) {
	sessions := NewInMemorySessions[*dummyCtx]()

	ctx := &dummyCtx{subject: "user-1"}
	err := sessions.Set("sess-1", ctx)
	require.NoError(t, err)

	got, err := sessions.Get("sess-1")
	require.NoError(t, err)
	assert.Equal(t, "user-1", got.subject)
}

func TestInMemorySessions_GetNotFound(t *testing.T) {
	sessions := NewInMemorySessions[*dummyCtx]()

	_, err := sessions.Get("nonexistent")
	assert.Error(t, err)
}

func TestInMemorySessions_Overwrite(t *testing.T) {
	sessions := NewInMemorySessions[*dummyCtx]()

	_ = sessions.Set("sess-1", &dummyCtx{subject: "first"})
	_ = sessions.Set("sess-1", &dummyCtx{subject: "second"})

	got, err := sessions.Get("sess-1")
	require.NoError(t, err)
	assert.Equal(t, "second", got.subject)
}

func TestInMemorySessions_ConcurrentAccess(t *testing.T) {
	sessions := NewInMemorySessions[*dummyCtx]()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = sessions.Set("key", &dummyCtx{subject: "user"})
				_, _ = sessions.Get("key")
			}
		}(i)
	}

	wg.Wait()
}
