package agent

import "testing"

func BenchmarkInventoryCollect(b *testing.B) {
	c := &Collector{Run: ExecRunner}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Collect()
	}
}
