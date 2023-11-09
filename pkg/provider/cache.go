package provider

type EmptyCache[K comparable, T any] struct{}

func (e *EmptyCache[K, T]) Set(_ K, _ T) error { return nil }
func (e *EmptyCache[K, T]) Get(_ K) (T, error) {
	var tnil T
	return tnil, nil
}

var _ Cache[string, string] = &EmptyCache[string, string]{}

type Cache[K comparable, T any] interface {
	Get(K) (T, error)
	Set(K, T) error
}
