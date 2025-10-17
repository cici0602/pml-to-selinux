package main

import (
	"fmt"
	"os"

	"github.com/cici0602/pml-to-selinux/compiler"
	"github.com/cici0602/pml-to-selinux/selinux"
	"github.com/spf13/cobra"
)

var (
	modelPath   string
	policyPath  string
	outputDir   string
	moduleName  string
	validate    bool
	optimize    bool
	verbose     bool
	modelPath2  string
	policyPath2 string
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

	// Diff command
	diffCmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two PML policies",
		Long:  "Compare two PML policy sets and show the differences",
		Run:   runDiff,
	}

	diffCmd.Flags().StringVarP(&modelPath, "model1", "m", "", "Path to first PML model file (required)")
	diffCmd.Flags().StringVarP(&policyPath, "policy1", "p", "", "Path to first PML policy file (required)")
	diffCmd.Flags().StringVar(&modelPath2, "model2", "", "Path to second PML model file (required)")
	diffCmd.Flags().StringVar(&policyPath2, "policy2", "", "Path to second PML policy file (required)")

	diffCmd.MarkFlagRequired("model1")
	diffCmd.MarkFlagRequired("policy1")
	diffCmd.MarkFlagRequired("model2")
	diffCmd.MarkFlagRequired("policy2")

	// Init command
	initCmd := &cobra.Command{
		Use:   "init [project-name]",
		Short: "Initialize a new PML project",
		Long:  "Create a new PML project with template files",
		Args:  cobra.ExactArgs(1),
		Run:   runInit,
	}

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
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(initCmd)
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

	// 2. Decode standard PML to SELinux structures
	if verbose {
		fmt.Println("⟳ Decoding PML to SELinux structures...")
	}
	decoded, err := parser.Decode(pml)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Decoding error: %v\n", err)
		os.Exit(1)
	}
	if verbose {
		fmt.Printf("✓ Decoded %d policies, %d transitions, %d booleans\n",
			len(decoded.Policies), len(decoded.Transitions), len(decoded.Booleans))
	}

	// 3. Analyze and validate
	if verbose {
		fmt.Println("⟳ Analyzing policy...")
	}
	analyzer := compiler.NewAnalyzer(decoded)
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

	// 4. Generate SELinux policy
	if verbose {
		fmt.Println("⟳ Generating SELinux policy...")
	}
	generator := compiler.NewGenerator(decoded, moduleName)
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

	// Generate .if file
	ifGenerator := selinux.NewIFGenerator(selinuxPolicy)
	ifContent, err := ifGenerator.Generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ IF generation error: %v\n", err)
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

	// Write .if file
	ifPath := fmt.Sprintf("%s/%s.if", outputDir, selinuxPolicy.ModuleName)
	if err := os.WriteFile(ifPath, []byte(ifContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to write .if file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Compilation successful!\n")
	fmt.Printf("  Generated: %s\n", tePath)
	fmt.Printf("  Generated: %s\n", fcPath)
	fmt.Printf("  Generated: %s\n", ifPath)

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

	// Decode
	decoded, err := parser.Decode(pml)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Decode error: %v\n", err)
		os.Exit(1)
	}

	// Analyze
	analyzer := compiler.NewAnalyzer(decoded)
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

	// Decode
	decoded, err := parser.Decode(pml)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Decode error: %v\n", err)
		os.Exit(1)
	}

	// Analyze
	analyzer := compiler.NewAnalyzer(decoded)
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

func runDiff(cmd *cobra.Command, args []string) {
	fmt.Println("Comparing PML policies...")

	// Parse and decode first policy
	parser1 := compiler.NewParser(modelPath, policyPath)
	pml1, err := parser1.Parse()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Error parsing first policy: %v\n", err)
		os.Exit(1)
	}
	decoded1, err := parser1.Decode(pml1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Error decoding first policy: %v\n", err)
		os.Exit(1)
	}

	// Generate first SELinux policy
	gen1 := compiler.NewGenerator(decoded1, "")
	policy1, err := gen1.Generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Error generating first policy: %v\n", err)
		os.Exit(1)
	}

	// Parse and decode second policy
	parser2 := compiler.NewParser(modelPath2, policyPath2)
	pml2, err := parser2.Parse()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Error parsing second policy: %v\n", err)
		os.Exit(1)
	}
	decoded2, err := parser2.Decode(pml2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Error decoding second policy: %v\n", err)
		os.Exit(1)
	}

	// Generate second SELinux policy
	gen2 := compiler.NewGenerator(decoded2, "")
	policy2, err := gen2.Generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Error generating second policy: %v\n", err)
		os.Exit(1)
	}

	// Compare policies
	differ := compiler.NewDiffer(policy1, policy2)
	diffResult := differ.Diff()

	// Display results
	fmt.Println("\nPolicy Comparison:")
	fmt.Printf("  Policy 1: %s/%s\n", modelPath, policyPath)
	fmt.Printf("  Policy 2: %s/%s\n\n", modelPath2, policyPath2)

	output := compiler.FormatDiff(diffResult)
	fmt.Print(output)
}

func runInit(cmd *cobra.Command, args []string) {
	projectName := args[0]
	fmt.Printf("Creating new PML project: %s\n", projectName)

	// Create project directory
	if err := os.MkdirAll(projectName, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to create project directory: %v\n", err)
		os.Exit(1)
	}

	// Template model file
	modelTemplate := `[request_definition]
r = sub, obj, act, class

[policy_definition]
p = sub, obj, act, class, eft

[role_definition]
g = _, _
g2 = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, p.sub) && matchPath(r.obj, p.obj) && r.act == p.act && r.class == p.class
`

	// Template policy file
	policyTemplate := `# Example policy for ` + projectName + `
# Format: p, subject, object, action, class, effect

# Allow ` + projectName + `_t to read config files
p, ` + projectName + `_t, /etc/` + projectName + `/*, read, file, allow

# Allow ` + projectName + `_t to write log files
p, ` + projectName + `_t, /var/log/` + projectName + `/*, write, file, allow

# Allow ` + projectName + `_t to manage data files
p, ` + projectName + `_t, /var/lib/` + projectName + `/*, read, file, allow
p, ` + projectName + `_t, /var/lib/` + projectName + `/*, write, file, allow

# Deny ` + projectName + `_t from accessing sensitive files
p, ` + projectName + `_t, /etc/shadow, read, file, deny
p, ` + projectName + `_t, /etc/passwd, write, file, deny

# Type transition example (optional)
# t, ` + projectName + `_t, tmp_t, file, ` + projectName + `_tmp_t

# Role relations example (optional)
# g, user_u, user_r
# g2, ` + projectName + `_t, domain
`

	// Template README
	readmeTemplate := `# ` + projectName + ` PML Project

This is a SELinux policy project using Casbin PML.

## Files

- **model.conf**: PML model definition
- **policy.csv**: PML policy rules
- **output/**: Generated SELinux policy files

## Usage

### Compile the policy
` + "```bash" + `
pml2selinux compile -m model.conf -p policy.csv -o output
` + "```" + `

### Validate the policy
` + "```bash" + `
pml2selinux validate -m model.conf -p policy.csv
` + "```" + `

### Analyze the policy
` + "```bash" + `
pml2selinux analyze -m model.conf -p policy.csv
` + "```" + `

### Install the generated policy
` + "```bash" + `
cd output
checkmodule -M -m -o ` + projectName + `.mod ` + projectName + `.te
semodule_package -o ` + projectName + `.pp -m ` + projectName + `.mod -fc ` + projectName + `.fc
sudo semodule -i ` + projectName + `.pp
` + "```" + `

## Documentation

For more information, see the [PML to SELinux documentation](https://github.com/cici0602/pml-to-selinux).
`

	// Write model.conf
	modelPath := fmt.Sprintf("%s/model.conf", projectName)
	if err := os.WriteFile(modelPath, []byte(modelTemplate), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to write model.conf: %v\n", err)
		os.Exit(1)
	}

	// Write policy.csv
	policyPath := fmt.Sprintf("%s/policy.csv", projectName)
	if err := os.WriteFile(policyPath, []byte(policyTemplate), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to write policy.csv: %v\n", err)
		os.Exit(1)
	}

	// Write README.md
	readmePath := fmt.Sprintf("%s/README.md", projectName)
	if err := os.WriteFile(readmePath, []byte(readmeTemplate), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to write README.md: %v\n", err)
		os.Exit(1)
	}

	// Create output directory
	outputPath := fmt.Sprintf("%s/output", projectName)
	if err := os.MkdirAll(outputPath, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Project created successfully!\n\n")
	fmt.Printf("Project structure:\n")
	fmt.Printf("  %s/\n", projectName)
	fmt.Printf("  ├── model.conf   (PML model)\n")
	fmt.Printf("  ├── policy.csv   (PML policies)\n")
	fmt.Printf("  ├── README.md    (Documentation)\n")
	fmt.Printf("  └── output/      (Generated files)\n\n")
	fmt.Printf("Next steps:\n")
	fmt.Printf("  cd %s\n", projectName)
	fmt.Printf("  pml2selinux compile -m model.conf -p policy.csv\n")
}
