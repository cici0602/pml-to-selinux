package selinux

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cici0602/pml-to-selinux/models"
)

// MacroGenerator handles generation of SELinux macros and require statements
type MacroGenerator struct {
	policy *models.SELinuxPolicy
}

// NewMacroGenerator creates a new MacroGenerator instance
func NewMacroGenerator(policy *models.SELinuxPolicy) *MacroGenerator {
	return &MacroGenerator{
		policy: policy,
	}
}

// GenerateRequireBlock generates a require block with all needed types, classes, and permissions
func (g *MacroGenerator) GenerateRequireBlock() string {
	var builder strings.Builder

	// Collect all types, classes, and permissions used
	types := make(map[string]bool)
	classes := make(map[string]map[string]bool) // class -> permissions

	// Extract from allow rules
	for _, rule := range g.policy.Rules {
		types[rule.SourceType] = true
		types[rule.TargetType] = true

		if classes[rule.Class] == nil {
			classes[rule.Class] = make(map[string]bool)
		}
		for _, perm := range rule.Permissions {
			classes[rule.Class][perm] = true
		}
	}

	// Extract from deny rules
	for _, rule := range g.policy.DenyRules {
		types[rule.SourceType] = true
		types[rule.TargetType] = true

		if classes[rule.Class] == nil {
			classes[rule.Class] = make(map[string]bool)
		}
		for _, perm := range rule.Permissions {
			classes[rule.Class][perm] = true
		}
	}

	// Extract from transitions
	for _, trans := range g.policy.Transitions {
		types[trans.SourceType] = true
		types[trans.TargetType] = true
		types[trans.NewType] = true

		if classes[trans.Class] == nil {
			classes[trans.Class] = make(map[string]bool)
		}
	}

	// Remove policy's own types from require block
	for _, typeDecl := range g.policy.Types {
		delete(types, typeDecl.TypeName)
	}

	if len(types) == 0 && len(classes) == 0 {
		return ""
	}

	builder.WriteString("require {\n")

	// Write type requirements
	if len(types) > 0 {
		typeList := make([]string, 0, len(types))
		for t := range types {
			typeList = append(typeList, t)
		}
		sort.Strings(typeList)

		for _, t := range typeList {
			builder.WriteString(fmt.Sprintf("\ttype %s;\n", t))
		}
	}

	// Write class requirements
	if len(classes) > 0 {
		classList := make([]string, 0, len(classes))
		for c := range classes {
			classList = append(classList, c)
		}
		sort.Strings(classList)

		for _, class := range classList {
			perms := make([]string, 0, len(classes[class]))
			for p := range classes[class] {
				perms = append(perms, p)
			}
			sort.Strings(perms)

			builder.WriteString(fmt.Sprintf("\tclass %s { %s };\n",
				class, strings.Join(perms, " ")))
		}
	}

	builder.WriteString("}\n\n")
	return builder.String()
}

// GenerateCommonMacros generates common SELinux macros for the module
func (g *MacroGenerator) GenerateCommonMacros() []models.MacroDefinition {
	macros := make([]models.MacroDefinition, 0)

	// Generate read macro
	readMacro := models.MacroDefinition{
		Name:        fmt.Sprintf("%s_read", g.policy.ModuleName),
		Description: fmt.Sprintf("Allow domain to read %s files", g.policy.ModuleName),
		Parameters:  []string{"domain"},
		Body: fmt.Sprintf(`gen_require(%s
		type %s_t;
	%s)

	allow $1 %s_t:file read_file_perms;
	allow $1 %s_t:dir list_dir_perms;
`, "`", g.policy.ModuleName, "'", g.policy.ModuleName, g.policy.ModuleName),
	}
	macros = append(macros, readMacro)

	// Generate write macro
	writeMacro := models.MacroDefinition{
		Name:        fmt.Sprintf("%s_write", g.policy.ModuleName),
		Description: fmt.Sprintf("Allow domain to write %s files", g.policy.ModuleName),
		Parameters:  []string{"domain"},
		Body: fmt.Sprintf(`gen_require(%s
		type %s_t;
	%s)

	allow $1 %s_t:file write_file_perms;
	allow $1 %s_t:dir rw_dir_perms;
`, "`", g.policy.ModuleName, "'", g.policy.ModuleName, g.policy.ModuleName),
	}
	macros = append(macros, writeMacro)

	// Generate execute macro
	executeMacro := models.MacroDefinition{
		Name:        fmt.Sprintf("%s_exec", g.policy.ModuleName),
		Description: fmt.Sprintf("Allow domain to execute %s binaries", g.policy.ModuleName),
		Parameters:  []string{"domain"},
		Body: fmt.Sprintf(`gen_require(%s
		type %s_exec_t;
	%s)

	can_exec($1, %s_exec_t)
`, "`", g.policy.ModuleName, "'", g.policy.ModuleName),
	}
	macros = append(macros, executeMacro)

	// Generate domain transition macro
	transitionMacro := models.MacroDefinition{
		Name:        fmt.Sprintf("%s_domtrans", g.policy.ModuleName),
		Description: fmt.Sprintf("Allow domain to transition to %s domain", g.policy.ModuleName),
		Parameters:  []string{"domain"},
		Body: fmt.Sprintf(`gen_require(%s
		type %s_t, %s_exec_t;
	%s)

	domtrans_pattern($1, %s_exec_t, %s_t)
`, "`", g.policy.ModuleName, g.policy.ModuleName, "'", g.policy.ModuleName, g.policy.ModuleName),
	}
	macros = append(macros, transitionMacro)

	return macros
}

// GenerateMacroFile generates the content for macros (can be included in .te or separate file)
func (g *MacroGenerator) GenerateMacroFile() string {
	var builder strings.Builder

	builder.WriteString("########################################\n")
	builder.WriteString(fmt.Sprintf("# SELinux Macros for %s\n", g.policy.ModuleName))
	builder.WriteString("# Generated by PML-to-SELinux Compiler\n")
	builder.WriteString("########################################\n\n")

	// Generate common macros
	macros := g.GenerateCommonMacros()

	for _, macro := range macros {
		builder.WriteString("########################################\n")
		builder.WriteString(fmt.Sprintf("## <summary>\n"))
		builder.WriteString(fmt.Sprintf("##\t%s\n", macro.Description))
		builder.WriteString("## </summary>\n")
		builder.WriteString("## <param name=\"domain\">\n")
		builder.WriteString("##\t<summary>\n")
		builder.WriteString("##\tDomain allowed access.\n")
		builder.WriteString("##\t</summary>\n")
		builder.WriteString("## </param>\n")
		builder.WriteString("#\n")
		builder.WriteString(fmt.Sprintf("interface(`%s',`\n", macro.Name))
		builder.WriteString(macro.Body)
		builder.WriteString("')\n\n")
	}

	// Add custom macros from policy
	for _, macro := range g.policy.Macros {
		builder.WriteString("########################################\n")
		builder.WriteString(fmt.Sprintf("## <summary>\n"))
		builder.WriteString(fmt.Sprintf("##\t%s\n", macro.Description))
		builder.WriteString("## </summary>\n")

		for i, param := range macro.Parameters {
			builder.WriteString(fmt.Sprintf("## <param name=\"%s\">\n", param))
			builder.WriteString("##\t<summary>\n")
			builder.WriteString(fmt.Sprintf("##\tParameter %d\n", i+1))
			builder.WriteString("##\t</summary>\n")
			builder.WriteString("## </param>\n")
		}

		builder.WriteString("#\n")
		builder.WriteString(fmt.Sprintf("interface(`%s',`\n", macro.Name))
		builder.WriteString(macro.Body)
		builder.WriteString("')\n\n")
	}

	return builder.String()
}

// GenerateRequireStatements analyzes the policy and generates appropriate require statements
func GenerateRequireStatements(policy *models.SELinuxPolicy) string {
	generator := NewMacroGenerator(policy)
	return generator.GenerateRequireBlock()
}

// GenerateMacros generates all macros for the policy
func GenerateMacros(policy *models.SELinuxPolicy) string {
	generator := NewMacroGenerator(policy)
	return generator.GenerateMacroFile()
}
