package proxy

import "testing"

func BenchmarkBytePoolGetPut(b *testing.B) {
	p := newBytePool()

	for b.Loop() {
		buf := p.Get()
		p.Put(buf)
	}
}

func TestBytePoolRejectsWrongSize(t *testing.T) {
	p := newBytePool()
	p.Put(make([]byte, 7))
	buf := p.Get()
	if len(buf) != 32*1024 {
		t.Fatalf("unexpected pool buf len %d", len(buf))
	}
}
