package compiler

import (
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
	"github.com/cici0602/pml-to-selinux/selinux"
	"github.com/stretchr/testify/assert"
)

// TestBooleanGeneration tests the generation of booleans
func TestBooleanGeneration(t *testing.T) {
	decoded := &models.DecodedPML{
		Model: &models.PMLModel{},
		Policies: []models.DecodedPolicy{},
		Roles: []models.RoleRelation{},
		TypeAttributes: []models.RoleRelation{},
		Booleans: []models.DecodedBoolean{
			{Name: "httpd_enable_homedirs", DefaultValue: false},
		},
		Transitions: []models.TransitionInfo{},
	}

	gen := NewGenerator(decoded, "testmodule")
	policy, err := gen.Generate()
	assert.NoError(t, err)
	assert.NotNil(t, policy)

	assert.Len(t, policy.Booleans, 1)
	assert.Equal(t, "httpd_enable_homedirs", policy.Booleans[0].Name)
	assert.False(t, policy.Booleans[0].DefaultValue)
}

// TestMacroGeneration tests the generation of macros
func TestMacroGeneration(t *testing.T) {
	decoded := &models.DecodedPML{
		Model: &models.PMLModel{},
		Policies: []models.DecodedPolicy{
			{
				Policy: models.Policy{
					Type: "p",
					Subject: "my_app",
					Object: "/data/app/*",
					Action: "read",
					Class: "file",
					Effect: "allow",
				},
			},
		},
		Roles: []models.RoleRelation{},
		TypeAttributes: []models.RoleRelation{},
		Booleans: []models.DecodedBoolean{},
		Transitions: []models.TransitionInfo{},
	}

	gen := NewGenerator(decoded, "my_app")
	policy, err := gen.Generate()
	assert.NoError(t, err)

	macroGen := selinux.NewMacroGenerator(policy)
	macros := macroGen.GenerateCommonMacros()

	assert.NotEmpty(t, macros)
	assert.Contains(t, macros[0].Name, "my_app_read")
}

// TestSemanageGeneration tests the generation of semanage commands
func TestSemanageGeneration(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "testmodule",
		Booleans: []models.BooleanDeclaration{
			{Name: "test_bool", DefaultValue: true},
		},
		FileContexts: []models.FileContext{
			{PathPattern: "/test(/.*)?", FileType: "test_t", Context: "u:object_r:test_t:s0"},
		},
	}

	semanageGen := selinux.NewSemanageGenerator(policy)
	commands := semanageGen.GenerateCommands()

	assert.NotEmpty(t, commands.BooleanCommands)
	assert.Contains(t, commands.BooleanCommands[0], "semanage boolean -m --on test_bool")

	assert.NotEmpty(t, commands.FileContextCommands)
	assert.Contains(t, commands.FileContextCommands[0], "semanage fcontext -a -t u:object_r:test_t:s0")
}

// TestOptimizer tests the policy optimizer
func TestOptimizer(t *testing.T) {
	policy := &models.SELinuxPolicy{
		Rules: []models.AllowRule{
			{SourceType: "a", TargetType: "b", Class: "c", Permissions: []string{"read"}},
			{SourceType: "a", TargetType: "b", Class: "c", Permissions: []string{"write"}},
		},
	}

	optimizer := NewOptimizer(policy)
	optimizer.Optimize()

	assert.Len(t, policy.Rules, 1)
	assert.ElementsMatch(t, []string{"read", "write"}, policy.Rules[0].Permissions)
}

// TestDiffer tests the policy differ
func TestDiffer(t *testing.T) {
	policy1 := &models.SELinuxPolicy{
		Types: []models.TypeDeclaration{{TypeName: "type1"}},
	}
	policy2 := &models.SELinuxPolicy{
		Types: []models.TypeDeclaration{{TypeName: "type2"}},
	}

	differ := NewDiffer(policy1, policy2)
	diff := differ.Diff()

	assert.Contains(t, diff.TypesAdded, "type2")
	assert.Contains(t, diff.TypesRemoved, "type1")
}
