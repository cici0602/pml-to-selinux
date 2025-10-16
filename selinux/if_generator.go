package selinux

import (
	"fmt"
	"strings"

	"github.com/cici0602/pml-to-selinux/models"
)

// IFGenerator handles generation of SELinux interface (.if) files
type IFGenerator struct {
	policy *models.SELinuxPolicy
}

// NewIFGenerator creates a new IFGenerator instance
func NewIFGenerator(policy *models.SELinuxPolicy) *IFGenerator {
	return &IFGenerator{
		policy: policy,
	}
}

// Generate generates the complete .if file content
func (g *IFGenerator) Generate() (string, error) {
	var builder strings.Builder

	// Write header
	g.writeHeader(&builder)

	// Generate common interfaces based on policy rules
	g.generateReadInterface(&builder)
	g.generateWriteInterface(&builder)
	g.generateExecuteInterface(&builder)
	g.generateDomainTransitionInterface(&builder)

	return builder.String(), nil
}

// writeHeader writes the interface file header
func (g *IFGenerator) writeHeader(builder *strings.Builder) {
	builder.WriteString("## <summary>\n")
	builder.WriteString(fmt.Sprintf("##\t%s policy module\n", g.policy.ModuleName))
	builder.WriteString("## </summary>\n\n")
}

// generateReadInterface generates read access interface
func (g *IFGenerator) generateReadInterface(builder *strings.Builder) {
	moduleName := g.policy.ModuleName

	builder.WriteString("########################################\n")
	builder.WriteString(fmt.Sprintf("## <summary>\n##\tRead %s files.\n## </summary>\n", moduleName))
	builder.WriteString("## <param name=\"domain\">\n")
	builder.WriteString("##\t<summary>\n##\tDomain allowed access.\n##\t</summary>\n")
	builder.WriteString("## </param>\n")
	builder.WriteString("#\n")
	builder.WriteString(fmt.Sprintf("interface(`%s_read_files',`\n", moduleName))
	builder.WriteString("\tgen_require(`\n")

	// Collect read-related types from rules
	typeSet := make(map[string]bool)
	for _, rule := range g.policy.Rules {
		if hasReadPerm(rule.Permissions) {
			typeSet[rule.TargetType] = true
		}
	}

	// Write type requirements
	for typeName := range typeSet {
		builder.WriteString(fmt.Sprintf("\t\ttype %s;\n", typeName))
	}
	builder.WriteString("\t')\n\n")

	// Write allow rules
	for typeName := range typeSet {
		builder.WriteString(fmt.Sprintf("\tallow $1 %s:file read_file_perms;\n", typeName))
	}

	builder.WriteString("')\n\n")
}

// generateWriteInterface generates write access interface
func (g *IFGenerator) generateWriteInterface(builder *strings.Builder) {
	moduleName := g.policy.ModuleName

	builder.WriteString("########################################\n")
	builder.WriteString(fmt.Sprintf("## <summary>\n##\tWrite %s files.\n## </summary>\n", moduleName))
	builder.WriteString("## <param name=\"domain\">\n")
	builder.WriteString("##\t<summary>\n##\tDomain allowed access.\n##\t</summary>\n")
	builder.WriteString("## </param>\n")
	builder.WriteString("#\n")
	builder.WriteString(fmt.Sprintf("interface(`%s_write_files',`\n", moduleName))
	builder.WriteString("\tgen_require(`\n")

	// Collect write-related types
	typeSet := make(map[string]bool)
	for _, rule := range g.policy.Rules {
		if hasWritePerm(rule.Permissions) {
			typeSet[rule.TargetType] = true
		}
	}

	for typeName := range typeSet {
		builder.WriteString(fmt.Sprintf("\t\ttype %s;\n", typeName))
	}
	builder.WriteString("\t')\n\n")

	for typeName := range typeSet {
		builder.WriteString(fmt.Sprintf("\tallow $1 %s:file write_file_perms;\n", typeName))
	}

	builder.WriteString("')\n\n")
}

// generateExecuteInterface generates execute access interface
func (g *IFGenerator) generateExecuteInterface(builder *strings.Builder) {
	moduleName := g.policy.ModuleName

	builder.WriteString("########################################\n")
	builder.WriteString(fmt.Sprintf("## <summary>\n##\tExecute %s files.\n## </summary>\n", moduleName))
	builder.WriteString("## <param name=\"domain\">\n")
	builder.WriteString("##\t<summary>\n##\tDomain allowed access.\n##\t</summary>\n")
	builder.WriteString("## </param>\n")
	builder.WriteString("#\n")
	builder.WriteString(fmt.Sprintf("interface(`%s_exec',`\n", moduleName))
	builder.WriteString("\tgen_require(`\n")

	// Collect execute-related types
	typeSet := make(map[string]bool)
	for _, rule := range g.policy.Rules {
		if hasExecutePerm(rule.Permissions) {
			typeSet[rule.TargetType] = true
		}
	}

	for typeName := range typeSet {
		builder.WriteString(fmt.Sprintf("\t\ttype %s;\n", typeName))
	}
	builder.WriteString("\t')\n\n")

	for typeName := range typeSet {
		builder.WriteString(fmt.Sprintf("\tcan_exec($1, %s)\n", typeName))
	}

	builder.WriteString("')\n\n")
}

// generateDomainTransitionInterface generates domain transition interface
func (g *IFGenerator) generateDomainTransitionInterface(builder *strings.Builder) {
	if len(g.policy.Transitions) == 0 {
		return
	}

	moduleName := g.policy.ModuleName

	builder.WriteString("########################################\n")
	builder.WriteString(fmt.Sprintf("## <summary>\n##\tTransition to %s domain.\n## </summary>\n", moduleName))
	builder.WriteString("## <param name=\"domain\">\n")
	builder.WriteString("##\t<summary>\n##\tDomain allowed to transition.\n##\t</summary>\n")
	builder.WriteString("## </param>\n")
	builder.WriteString("#\n")
	builder.WriteString(fmt.Sprintf("interface(`%s_domtrans',`\n", moduleName))
	builder.WriteString("\tgen_require(`\n")

	// Collect types from transitions
	typeSet := make(map[string]bool)
	for _, trans := range g.policy.Transitions {
		typeSet[trans.SourceType] = true
		typeSet[trans.TargetType] = true
		typeSet[trans.NewType] = true
	}

	for typeName := range typeSet {
		builder.WriteString(fmt.Sprintf("\t\ttype %s;\n", typeName))
	}
	builder.WriteString("\t')\n\n")

	for _, trans := range g.policy.Transitions {
		builder.WriteString(fmt.Sprintf("\tdomtrans_pattern($1, %s, %s)\n",
			trans.TargetType, trans.NewType))
	}

	builder.WriteString("')\n\n")
}

// Helper functions
func hasReadPerm(perms []string) bool {
	for _, p := range perms {
		if p == "read" || p == "getattr" || p == "open" {
			return true
		}
	}
	return false
}

func hasWritePerm(perms []string) bool {
	for _, p := range perms {
		if p == "write" || p == "append" || p == "create" {
			return true
		}
	}
	return false
}

func hasExecutePerm(perms []string) bool {
	for _, p := range perms {
		if p == "execute" || p == "execute_no_trans" {
			return true
		}
	}
	return false
}
