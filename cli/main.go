package main

import (
	"fmt"
	"os"

	"github.com/cici0602/pml-to-selinux/compiler"
	"github.com/cici0602/pml-to-selinux/selinux"
	"github.com/spf13/cobra"
)

var (
	modelPath  string
	policyPath string
	outputDir  string
	moduleName string
	validate   bool
	optimize   bool
	verbose    bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "pml2selinux",
		Short: "Compile Casbin PML to SELinux policies",
		Long: `pml2selinux is a compiler that translates Casbin PML (Policy Modeling Language)
into SELinux policy files (.te, .fc, .if).

This allows you to write security policies in a higher-level, more abstract
language and automatically generate SELinux policies.`,
	}

	// Compile command
	compileCmd := &cobra.Command{
		Use:   "compile",
		Short: "Compile PML to SELinux policy",
		Long:  "Compile Casbin PML model and policy files into SELinux policy files",
		Run:   runCompile,
	}

	compileCmd.Flags().StringVarP(&modelPath, "model", "m", "", "Path to PML model file (required)")
	compileCmd.Flags().StringVarP(&policyPath, "policy", "p", "", "Path to PML policy file (required)")
	compileCmd.Flags().StringVarP(&outputDir, "output", "o", "./output", "Output directory for generated files")
	compileCmd.Flags().StringVarP(&moduleName, "name", "n", "", "Module name (default: inferred from policy)")
	compileCmd.Flags().BoolVarP(&validate, "validate", "v", false, "Validate generated policy")
	compileCmd.Flags().BoolVar(&optimize, "optimize", true, "Optimize generated policy")
	compileCmd.Flags().BoolVar(&verbose, "verbose", false, "Enable verbose output")

	compileCmd.MarkFlagRequired("model")
	compileCmd.MarkFlagRequired("policy")

	// Validate command
	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate PML files",
		Long:  "Validate PML model and policy files without generating output",
		Run:   runValidate,
	}

	validateCmd.Flags().StringVarP(&modelPath, "model", "m", "", "Path to PML model file (required)")
	validateCmd.Flags().StringVarP(&policyPath, "policy", "p", "", "Path to PML policy file (required)")
	validateCmd.Flags().BoolVar(&verbose, "verbose", false, "Enable verbose output")

	validateCmd.MarkFlagRequired("model")
	validateCmd.MarkFlagRequired("policy")

	// Analyze command
	analyzeCmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze PML policy",
		Long:  "Analyze PML policy and display statistics and potential issues",
		Run:   runAnalyze,
	}

	analyzeCmd.Flags().StringVarP(&modelPath, "model", "m", "", "Path to PML model file (required)")
	analyzeCmd.Flags().StringVarP(&policyPath, "policy", "p", "", "Path to PML policy file (required)")

	analyzeCmd.MarkFlagRequired("model")
	analyzeCmd.MarkFlagRequired("policy")

	// Version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("pml2selinux version 0.1.0")
		},
	}

	rootCmd.AddCommand(compileCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runCompile(cmd *cobra.Command, args []string) {
	if verbose {
		fmt.Printf("Compiling PML to SELinux policy...\n")
		fmt.Printf("  Model:  %s\n", modelPath)
		fmt.Printf("  Policy: %s\n", policyPath)
		fmt.Printf("  Output: %s\n", outputDir)
		fmt.Println()
	}

	// 1. Parse PML files
	if verbose {
		fmt.Println("⟳ Parsing PML files...")
	}
	parser := compiler.NewParser(modelPath, policyPath)
	pml, err := parser.Parse()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Parse error: %v\n", err)
		os.Exit(1)
	}
	if verbose {
		fmt.Printf("✓ Successfully parsed model and %d policies\n", len(pml.Policies))
	}

	// 2. Analyze and validate
	if verbose {
		fmt.Println("⟳ Analyzing policy...")
	}
	analyzer := compiler.NewAnalyzer(pml)
	err = analyzer.Analyze()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Analysis error: %v\n", err)
		os.Exit(1)
	}
	stats := analyzer.GetStats()
	if verbose {
		fmt.Printf("✓ Analysis complete: %d rules, %d subjects, %d objects\n",
			stats.TotalPolicies, stats.UniqueSubjects, stats.UniqueObjects)
		if stats.Conflicts > 0 {
			fmt.Printf("⚠ Warning: Found %d potential conflicts\n", stats.Conflicts)
		}
	}

	// 3. Generate SELinux policy
	if verbose {
		fmt.Println("⟳ Generating SELinux policy...")
	}
	generator := compiler.NewGenerator(pml, moduleName)
	selinuxPolicy, err := generator.Generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Generation error: %v\n", err)
		os.Exit(1)
	}
	if verbose {
		fmt.Printf("✓ Generated %d types, %d allow rules, %d deny rules, %d file contexts\n",
			len(selinuxPolicy.Types), len(selinuxPolicy.Rules),
			len(selinuxPolicy.DenyRules), len(selinuxPolicy.FileContexts))
	}

	// 4. Optimize if requested
	if optimize {
		if verbose {
			fmt.Println("⟳ Optimizing policy...")
		}
		optimizer := compiler.NewOptimizer(selinuxPolicy)
		err = optimizer.Optimize()
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ Optimization error: %v\n", err)
			os.Exit(1)
		}
		if verbose {
			fmt.Printf("✓ Optimized: %d types, %d rules\n",
				len(selinuxPolicy.Types), len(selinuxPolicy.Rules))
		}
	}

	// 5. Write output files
	if verbose {
		fmt.Printf("⟳ Writing files to %s...\n", outputDir)
	}

	// Generate .te file
	teGenerator := selinux.NewTEGenerator(selinuxPolicy)
	teContent, err := teGenerator.Generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ TE generation error: %v\n", err)
		os.Exit(1)
	}

	// Generate .fc file
	fcGenerator := selinux.NewFCGenerator(selinuxPolicy)
	fcContent, err := fcGenerator.Generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ FC generation error: %v\n", err)
		os.Exit(1)
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	// Write .te file
	tePath := fmt.Sprintf("%s/%s.te", outputDir, selinuxPolicy.ModuleName)
	if err := os.WriteFile(tePath, []byte(teContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to write .te file: %v\n", err)
		os.Exit(1)
	}

	// Write .fc file
	fcPath := fmt.Sprintf("%s/%s.fc", outputDir, selinuxPolicy.ModuleName)
	if err := os.WriteFile(fcPath, []byte(fcContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to write .fc file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Compilation successful!\n")
	fmt.Printf("  Generated: %s\n", tePath)
	fmt.Printf("  Generated: %s\n", fcPath)

	if validate {
		fmt.Println("\nℹ To validate and install the policy, run:")
		fmt.Printf("  checkmodule -M -m -o %s.mod %s\n", selinuxPolicy.ModuleName, tePath)
		fmt.Printf("  semodule_package -o %s.pp -m %s.mod -fc %s\n",
			selinuxPolicy.ModuleName, selinuxPolicy.ModuleName, fcPath)
		fmt.Printf("  sudo semodule -i %s.pp\n", selinuxPolicy.ModuleName)
	}
}

func runValidate(cmd *cobra.Command, args []string) {
	if verbose {
		fmt.Println("Validating PML files...")
	}

	// Parse
	parser := compiler.NewParser(modelPath, policyPath)
	pml, err := parser.Parse()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Parse error: %v\n", err)
		os.Exit(1)
	}

	// Analyze
	analyzer := compiler.NewAnalyzer(pml)
	err = analyzer.Analyze()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Validation failed: %v\n", err)
		os.Exit(1)
	}

	stats := analyzer.GetStats()
	fmt.Println("✓ Validation successful!")
	fmt.Printf("  Total policies: %d\n", stats.TotalPolicies)
	fmt.Printf("  Allow rules:    %d\n", stats.AllowRules)
	fmt.Printf("  Deny rules:     %d\n", stats.DenyRules)

	if stats.Conflicts > 0 {
		fmt.Printf("\n⚠ Warning: Found %d potential conflicts\n", stats.Conflicts)
		conflicts := analyzer.GetConflicts()
		for i, conflict := range conflicts {
			fmt.Printf("  %d. %s\n", i+1, conflict.Reason)
		}
	}
}

func runAnalyze(cmd *cobra.Command, args []string) {
	fmt.Println("Analyzing PML policy...")

	// Parse
	parser := compiler.NewParser(modelPath, policyPath)
	pml, err := parser.Parse()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Parse error: %v\n", err)
		os.Exit(1)
	}

	// Analyze
	analyzer := compiler.NewAnalyzer(pml)
	err = analyzer.Analyze()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Analysis error: %v\n", err)
		os.Exit(1)
	}

	// Display statistics
	stats := analyzer.GetStats()
	fmt.Println("\n=== Policy Statistics ===")
	fmt.Printf("Total Policies:    %d\n", stats.TotalPolicies)
	fmt.Printf("Allow Rules:       %d\n", stats.AllowRules)
	fmt.Printf("Deny Rules:        %d\n", stats.DenyRules)
	fmt.Printf("Unique Subjects:   %d\n", stats.UniqueSubjects)
	fmt.Printf("Unique Objects:    %d\n", stats.UniqueObjects)
	fmt.Printf("Unique Actions:    %d\n", stats.UniqueActions)
	fmt.Printf("Role Relations:    %d\n", stats.RoleRelations)
	fmt.Printf("Conflicts:         %d\n", stats.Conflicts)

	if len(stats.SubjectTypes) > 0 {
		fmt.Println("\n=== Subject Types ===")
		for subject, count := range stats.SubjectTypes {
			fmt.Printf("  %-30s %d rules\n", subject, count)
		}
	}

	if len(stats.ActionTypes) > 0 {
		fmt.Println("\n=== Action Types ===")
		for action, count := range stats.ActionTypes {
			fmt.Printf("  %-20s %d times\n", action, count)
		}
	}

	if stats.Conflicts > 0 {
		fmt.Println("\n=== Conflicts ===")
		conflicts := analyzer.GetConflicts()
		for i, conflict := range conflicts {
			fmt.Printf("%d. %s\n", i+1, conflict.Reason)
			fmt.Printf("   Allow: %s -> %s [%s]\n",
				conflict.AllowRule.Subject, conflict.AllowRule.Object, conflict.AllowRule.Action)
			fmt.Printf("   Deny:  %s -> %s [%s]\n",
				conflict.DenyRule.Subject, conflict.DenyRule.Object, conflict.DenyRule.Action)
		}
	}

	fmt.Println("\n✓ Analysis complete")
}
