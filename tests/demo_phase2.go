package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cici0602/pml-to-selinux/compiler"
	"github.com/cici0602/pml-to-selinux/mapping"
	"github.com/cici0602/pml-to-selinux/models"
	"github.com/cici0602/pml-to-selinux/selinux"
)

func main() {
	fmt.Println("=== PML to SELinux Phase 2 Demo ===")
	fmt.Println()

	// Get the examples directory
	examplesDir := "../examples/httpd"
	if len(os.Args) > 1 {
		examplesDir = os.Args[1]
	}

	modelPath := filepath.Join(examplesDir, "httpd_model.conf")
	policyPath := filepath.Join(examplesDir, "httpd_policy.csv")

	// Step 1: Parse PML files
	fmt.Println("Step 1: Parsing PML files...")
	fmt.Printf("  Model: %s\n", modelPath)
	fmt.Printf("  Policy: %s\n", policyPath)

	parser := compiler.NewParser(modelPath, policyPath)
	pml, err := parser.Parse()
	if err != nil {
		log.Fatalf("Failed to parse PML: %v", err)
	}
	fmt.Printf("✓ Parsed %d policies\n\n", len(pml.Policies))

	// Step 2: Analyze PML
	fmt.Println("Step 2: Analyzing PML...")
	analyzer := compiler.NewAnalyzer(pml)
	if err := analyzer.Analyze(); err != nil {
		log.Fatalf("Failed to analyze PML: %v", err)
	}
	fmt.Printf("✓ Analysis complete\n\n")

	// Step 3: Generate SELinux policy
	fmt.Println("Step 3: Generating SELinux policy...")
	selinuxPolicy := generateSELinuxPolicy(pml, "httpd", "1.0.0")
	fmt.Printf("✓ Generated %d types\n", len(selinuxPolicy.Types))
	fmt.Printf("✓ Generated %d allow rules\n", len(selinuxPolicy.Rules))
	fmt.Printf("✓ Generated %d deny rules\n", len(selinuxPolicy.DenyRules))
	fmt.Printf("✓ Generated %d file contexts\n\n", len(selinuxPolicy.FileContexts))

	// Step 4: Optimize policy
	fmt.Println("Step 4: Optimizing policy...")
	originalRuleCount := len(selinuxPolicy.Rules)
	optimizer := compiler.NewOptimizer(selinuxPolicy)
	if err := optimizer.Optimize(); err != nil {
		log.Fatalf("Failed to optimize policy: %v", err)
	}
	fmt.Printf("✓ Optimized rules from %d to %d\n\n", originalRuleCount, len(selinuxPolicy.Rules))

	// Step 5: Generate .te file
	fmt.Println("Step 5: Generating .te file...")
	teContent, err := selinux.GenerateTE(selinuxPolicy)
	if err != nil {
		log.Fatalf("Failed to generate .te file: %v", err)
	}
	fmt.Println("✓ Generated .te file content (first 50 lines):")
	printFirstNLines(teContent, 50)

	// Step 6: Generate .fc file
	fmt.Println("\nStep 6: Generating .fc file...")
	fcContent, err := selinux.GenerateFC(selinuxPolicy)
	if err != nil {
		log.Fatalf("Failed to generate .fc file: %v", err)
	}
	fmt.Println("✓ Generated .fc file content:")
	printFirstNLines(fcContent, 30)

	// Step 7: Demonstrate mapping examples
	fmt.Println("\n\nStep 7: Demonstrating path and type mappings...")
	demonstrateMappings()

	fmt.Println("\n=== Demo Complete ===")
	fmt.Println("\nTo save output files, run:")
	fmt.Println("  go run demo_phase2.go > output.txt")
}

// generateSELinuxPolicy converts PML to SELinux policy
func generateSELinuxPolicy(pml *models.ParsedPML, moduleName, version string) *models.SELinuxPolicy {
	policy := models.NewSELinuxPolicy(moduleName, version)

	// Create mappers
	pathMapper := mapping.NewPathMapper()
	typeMapper := mapping.NewTypeMapper(moduleName)

	// Track unique types and file contexts
	typeSet := make(map[string]bool)
	contextMap := make(map[string]models.FileContext)

	// Process each policy
	for _, p := range pml.Policies {
		// Convert subject to type
		sourceType := typeMapper.SubjectToType(p.Subject)
		typeSet[sourceType] = true

		// Convert object path to target type
		targetType := typeMapper.PathToType(p.Object)
		typeSet[targetType] = true

		// Create file context for this object
		selinuxPattern := pathMapper.ConvertToSELinuxPattern(p.Object)

		contextKey := selinuxPattern + "|" + targetType
		if _, exists := contextMap[contextKey]; !exists {
			contextMap[contextKey] = models.FileContext{
				PathPattern: selinuxPattern,
				FileType:    targetType,
				User:        "system_u",
				Role:        "object_r",
				Level:       "s0",
			}
		}

		// Add allow or deny rule
		if p.Effect == "allow" {
			policy.AddAllowRule(models.AllowRule{
				SourceType:     sourceType,
				TargetType:     targetType,
				Class:          p.Class,
				Permissions:    []string{p.Action},
				OriginalObject: p.Object,
			})
		} else if p.Effect == "deny" {
			policy.AddDenyRule(models.DenyRule{
				SourceType:     sourceType,
				TargetType:     targetType,
				Class:          p.Class,
				Permissions:    []string{p.Action},
				OriginalObject: p.Object,
			})
		}

		// Infer type attributes
		targetAttributes := typeMapper.InferTypeCategory(p.Object)
		if len(targetAttributes) > 0 {
			// Add type with attributes if not already added
			if !policy.HasType(targetType) {
				policy.AddType(targetType, targetAttributes...)
			}
		}
	}

	// Add all unique types (including source types without attributes)
	for typeName := range typeSet {
		if !policy.HasType(typeName) {
			// Source types get "domain" attribute
			policy.AddType(typeName, "domain")
		}
	}

	// Add all file contexts
	for _, fc := range contextMap {
		policy.AddFileContext(fc)
	}

	return policy
}

// printFirstNLines prints the first N lines of a string
func printFirstNLines(content string, n int) {
	fmt.Println("─────────────────────────────────────")
	lines := 0
	for i, ch := range content {
		if ch == '\n' {
			lines++
			if lines >= n {
				fmt.Println("...")
				fmt.Printf("(Total: %d characters)\n", len(content))
				break
			}
		}
		fmt.Print(string(ch))
		if i == len(content)-1 {
			fmt.Println()
		}
	}
	fmt.Println("─────────────────────────────────────")
}

// demonstrateMappings shows example mappings
func demonstrateMappings() {
	pathMapper := mapping.NewPathMapper()
	typeMapper := mapping.NewTypeMapper("httpd")

	examples := []struct {
		casbinPath string
		desc       string
	}{
		{"/var/www/*", "Web content directory"},
		{"/etc/*.conf", "Config files with wildcard"},
		{"/var/log/httpd/*", "Log directory"},
		{"/usr/bin/httpd", "Binary executable"},
	}

	for _, ex := range examples {
		fmt.Printf("\n  Path: %s (%s)\n", ex.casbinPath, ex.desc)

		selinuxPattern := pathMapper.ConvertToSELinuxPattern(ex.casbinPath)
		fmt.Printf("    SELinux Pattern: %s\n", selinuxPattern)

		typeName := typeMapper.PathToType(ex.casbinPath)
		fmt.Printf("    Type Name: %s\n", typeName)

		fileType := pathMapper.InferFileType(ex.casbinPath)
		fmt.Printf("    File Type: %s\n", fileType)

		attributes := typeMapper.InferTypeCategory(ex.casbinPath)
		if len(attributes) > 0 {
			fmt.Printf("    Attributes: %v\n", attributes)
		}
	}
}
