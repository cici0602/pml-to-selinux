package compiler

import (
	"fmt"
	"strings"

	"github.com/cici0602/pml-to-selinux/mapping"
	"github.com/cici0602/pml-to-selinux/models"
)

// Generator orchestrates the conversion from PML to SELinux policy
type Generator struct {
	pml        *models.ParsedPML
	moduleName string
	typeMapper *mapping.TypeMapper
	pathMapper *mapping.PathMapper
}

// NewGenerator creates a new Generator instance
func NewGenerator(pml *models.ParsedPML, moduleName string) *Generator {
	return &Generator{
		pml:        pml,
		moduleName: moduleName,
		typeMapper: mapping.NewTypeMapper(moduleName),
		pathMapper: mapping.NewPathMapper(),
	}
}

// Generate converts parsed PML to SELinux policy
func (g *Generator) Generate() (*models.SELinuxPolicy, error) {
	if g.pml == nil {
		return nil, fmt.Errorf("parsed PML cannot be nil")
	}

	// Infer module name if not provided
	moduleName := g.moduleName
	if moduleName == "" {
		moduleName = g.inferModuleName()
	}

	policy := &models.SELinuxPolicy{
		ModuleName:   moduleName,
		Version:      "1.0.0",
		Types:        make([]models.TypeDeclaration, 0),
		Rules:        make([]models.AllowRule, 0),
		DenyRules:    make([]models.DenyRule, 0),
		Transitions:  make([]models.TypeTransition, 0),
		FileContexts: make([]models.FileContext, 0),
	}

	// Extract types from subjects and objects
	types := g.extractTypes()
	for typeName := range types {
		policy.Types = append(policy.Types, models.TypeDeclaration{
			TypeName: typeName,
		})
	}

	// Convert policies to SELinux rules
	if err := g.convertPolicies(policy); err != nil {
		return nil, err
	}

	// Convert transitions
	if err := g.convertTransitions(policy); err != nil {
		return nil, err
	}

	// Generate file contexts from object paths
	if err := g.generateFileContexts(policy); err != nil {
		return nil, err
	}

	return policy, nil
}

// inferModuleName infers module name from policy structure
func (g *Generator) inferModuleName() string {
	// Try to extract from first policy subject
	if len(g.pml.Policies) > 0 {
		subject := g.pml.Policies[0].Subject
		// Clean and sanitize the subject name
		name := strings.ToLower(subject)
		name = strings.ReplaceAll(name, "_process", "")
		name = strings.ReplaceAll(name, "_t", "")
		return name
	}
	return "myapp"
}

// extractTypes extracts unique type names from subjects and objects
func (g *Generator) extractTypes() map[string]bool {
	types := make(map[string]bool)

	for _, policy := range g.pml.Policies {
		// Add subject type
		subjectType := g.typeMapper.SubjectToType(policy.Subject)
		types[subjectType] = true

		// Add object type from path
		if strings.HasPrefix(policy.Object, "/") {
			objectType := g.typeMapper.PathToType(policy.Object)
			types[objectType] = true
		}
	}

	return types
}

// convertPolicies converts PML policies to SELinux rules
func (g *Generator) convertPolicies(policy *models.SELinuxPolicy) error {
	for _, pmlPolicy := range g.pml.Policies {
		sourceType := g.typeMapper.SubjectToType(pmlPolicy.Subject)

		// Determine target type based on object
		var targetType string
		if strings.HasPrefix(pmlPolicy.Object, "/") {
			targetType = g.typeMapper.PathToType(pmlPolicy.Object)
		} else {
			targetType = g.typeMapper.SubjectToType(pmlPolicy.Object)
		}

		// Map action to SELinux class and permissions
		class, perms := g.actionToPermissions(pmlPolicy.Action)

		if pmlPolicy.Effect == "allow" {
			rule := models.AllowRule{
				SourceType:  sourceType,
				TargetType:  targetType,
				Class:       class,
				Permissions: perms,
			}
			policy.Rules = append(policy.Rules, rule)
		} else if pmlPolicy.Effect == "deny" {
			rule := models.DenyRule{
				SourceType:  sourceType,
				TargetType:  targetType,
				Class:       class,
				Permissions: perms,
			}
			policy.DenyRules = append(policy.DenyRules, rule)
		}
	}

	return nil
}

// convertTransitions converts PML transitions to SELinux type_transition rules
func (g *Generator) convertTransitions(policy *models.SELinuxPolicy) error {
	for _, trans := range g.pml.Transitions {
		// Ensure transition types are added to policy
		selinuxTrans := models.TypeTransition{
			SourceType: trans.SourceType,
			TargetType: trans.TargetType,
			Class:      trans.Class,
			NewType:    trans.NewType,
		}
		policy.Transitions = append(policy.Transitions, selinuxTrans)

		// Ensure all types are declared
		g.ensureType(policy, trans.SourceType)
		g.ensureType(policy, trans.TargetType)
		g.ensureType(policy, trans.NewType)
	}
	return nil
}

// ensureType ensures a type is declared in the policy
func (g *Generator) ensureType(policy *models.SELinuxPolicy, typeName string) {
	for _, t := range policy.Types {
		if t.TypeName == typeName {
			return
		}
	}
	policy.Types = append(policy.Types, models.TypeDeclaration{
		TypeName: typeName,
	})
}

// actionToPermissions maps PML action to SELinux class and permissions
func (g *Generator) actionToPermissions(action string) (string, []string) {
	// Default to file class
	class := "file"
	var permissions []string

	actionLower := strings.ToLower(action)

	// Map common actions
	switch actionLower {
	case "read":
		permissions = []string{"read", "open", "getattr"}
	case "write":
		permissions = []string{"write", "append", "open"}
	case "execute", "exec":
		permissions = []string{"execute", "execute_no_trans"}
	case "create":
		permissions = []string{"create", "write", "open"}
	case "delete":
		permissions = []string{"unlink"}
	case "rename":
		permissions = []string{"rename"}
	case "append":
		permissions = []string{"append", "open"}
	case "search":
		class = "dir"
		permissions = []string{"search", "open"}
	case "list":
		class = "dir"
		permissions = []string{"read", "search", "open"}
	default:
		// Try to parse comma-separated permissions
		if strings.Contains(action, ",") {
			permissions = strings.Split(action, ",")
			for i, perm := range permissions {
				permissions[i] = strings.TrimSpace(perm)
			}
		} else {
			permissions = []string{action}
		}
	}

	return class, permissions
}

// generateFileContexts generates file context entries
func (g *Generator) generateFileContexts(policy *models.SELinuxPolicy) error {
	seenPaths := make(map[string]bool)

	for _, pmlPolicy := range g.pml.Policies {
		// Only generate contexts for file paths
		if !strings.HasPrefix(pmlPolicy.Object, "/") {
			continue
		}

		if seenPaths[pmlPolicy.Object] {
			continue
		}
		seenPaths[pmlPolicy.Object] = true

		// Convert path pattern to SELinux regex
		pathPattern := g.pathMapper.ConvertToSELinuxPattern(pmlPolicy.Object)
		objectType := g.typeMapper.PathToType(pmlPolicy.Object)

		// Determine file type from path
		fileType := g.pathMapper.InferFileType(pmlPolicy.Object)

		fc := models.FileContext{
			PathPattern: pathPattern,
			FileType:    fileType,
			User:        "system_u",
			Role:        "object_r",
			Level:       "s0",
		}
		fc.Context = fmt.Sprintf("%s:%s:%s:%s", fc.User, fc.Role, objectType, fc.Level)

		policy.FileContexts = append(policy.FileContexts, fc)
	}

	return nil
}
