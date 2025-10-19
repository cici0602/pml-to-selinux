package compiler

import (
	"testing"
)

// BenchmarkParser 测试解析性能
func BenchmarkParser(b *testing.B) {
	modelPath := "../examples/httpd/httpd_model.conf"
	policyPath := "../examples/httpd/httpd_policy.csv"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser := NewParser(modelPath, policyPath)
		_, err := parser.Parse()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAnalyzer 测试分析性能
func BenchmarkAnalyzer(b *testing.B) {
	parser := NewParser("../examples/httpd/httpd_model.conf", "../examples/httpd/httpd_policy.csv")
	pml, _ := parser.Parse()
	decoded, _ := parser.Decode(pml)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer := NewAnalyzer(decoded)
		if err := analyzer.Analyze(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGenerator 测试生成性能
func BenchmarkGenerator(b *testing.B) {
	parser := NewParser("../examples/httpd/httpd_model.conf", "../examples/httpd/httpd_policy.csv")
	pml, _ := parser.Parse()
	decoded, _ := parser.Decode(pml)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		generator := NewGenerator(decoded, "")
		_, err := generator.Generate()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkOptimizer 测试优化性能
// TODO: Optimization feature is not yet implemented
// func BenchmarkOptimizer(b *testing.B) {
// 	parser := NewParser("../examples/httpd/httpd_model.conf", "../examples/httpd/httpd_policy.csv")
// 	pml, _ := parser.Parse()
// 	decoded, _ := parser.Decode(pml)
// 	generator := NewGenerator(decoded, "")
// 	sePolicy, _ := generator.Generate()
//
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		// Optimization not implemented
// 	}
// }

// BenchmarkFullPipeline 测试完整流程性能
func BenchmarkFullPipeline(b *testing.B) {
	modelPath := "../examples/httpd/httpd_model.conf"
	policyPath := "../examples/httpd/httpd_policy.csv"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Parse
		parser := NewParser(modelPath, policyPath)
		pml, err := parser.Parse()
		if err != nil {
			b.Fatal(err)
		}

		// Decode
		decoded, err := parser.Decode(pml)
		if err != nil {
			b.Fatal(err)
		}

		// Analyze
		analyzer := NewAnalyzer(decoded)
		if err := analyzer.Analyze(); err != nil {
			b.Fatal(err)
		}

		// Generate
		generator := NewGenerator(decoded, "")
		_, err = generator.Generate()
		if err != nil {
			b.Fatal(err)
		}

		// Optimize
		// TODO: Optimization feature is not yet implemented
	}
}
