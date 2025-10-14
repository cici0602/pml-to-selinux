package main

import (
	"fmt"
	"os"

	"github.com/cici0602/pml-to-selinux/compiler"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: demo <model_file> <policy_file>")
		os.Exit(1)
	}

	modelPath := os.Args[1]
	policyPath := os.Args[2]

	fmt.Println("=== PML Parser and Analyzer Demo ===")
	fmt.Printf("Model file: %s\n", modelPath)
	fmt.Printf("Policy file: %s\n\n", policyPath)

	// Parse
	fmt.Println("1. Parsing PML files...")
	parser := compiler.NewParser(modelPath, policyPath)
	pml, err := parser.Parse()
	if err != nil {
		fmt.Printf("Error parsing: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Successfully parsed model and policies\n\n")

	// Display model info
	fmt.Println("2. Model Information:")
	fmt.Printf("   Request Definition: %v\n", pml.Model.RequestDefinition)
	fmt.Printf("   Policy Definition: %v\n", pml.Model.PolicyDefinition)
	fmt.Printf("   Matchers: %s\n", pml.Model.Matchers)
	fmt.Printf("   Effect: %s\n\n", pml.Model.Effect)

	// Analyze
	fmt.Println("3. Analyzing policies...")
	analyzer := compiler.NewAnalyzer(pml)
	err = analyzer.Analyze()
	if err != nil {
		fmt.Printf("Error analyzing: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Analysis completed\n\n")

	// Display statistics
	stats := analyzer.GetStats()
	fmt.Println("4. Policy Statistics:")
	fmt.Printf("   Total Policies: %d\n", stats.TotalPolicies)
	fmt.Printf("   Allow Rules: %d\n", stats.AllowRules)
	fmt.Printf("   Deny Rules: %d\n", stats.DenyRules)
	fmt.Printf("   Unique Subjects: %d\n", stats.UniqueSubjects)
	fmt.Printf("   Unique Objects: %d\n", stats.UniqueObjects)
	fmt.Printf("   Unique Actions: %d\n", stats.UniqueActions)
	fmt.Printf("   Role Relations: %d\n", stats.RoleRelations)
	fmt.Printf("   Conflicts Detected: %d\n\n", stats.Conflicts)

	// Display subject breakdown
	if len(stats.SubjectTypes) > 0 {
		fmt.Println("5. Rules by Subject:")
		for subject, count := range stats.SubjectTypes {
			fmt.Printf("   %s: %d rules\n", subject, count)
		}
		fmt.Println()
	}

	// Display action breakdown
	if len(stats.ActionTypes) > 0 {
		fmt.Println("6. Rules by Action:")
		for action, count := range stats.ActionTypes {
			fmt.Printf("   %s: %d rules\n", action, count)
		}
		fmt.Println()
	}

	// Display sample policies
	fmt.Println("7. Sample Policies (first 5):")
	for i, policy := range pml.Policies {
		if i >= 5 {
			fmt.Printf("   ... and %d more policies\n", len(pml.Policies)-5)
			break
		}
		fmt.Printf("   %s -> %s : %s on %s [%s]\n",
			policy.Subject, policy.Object, policy.Action, policy.Class, policy.Effect)
	}

	fmt.Println("\n✓ Demo completed successfully!")
}
