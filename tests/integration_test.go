package tests

import (
	"testing"

	"github.com/cici0602/pml-to-selinux/compiler"
	"github.com/cici0602/pml-to-selinux/models"
)

func TestBasicPolicyGeneration(t *testing.T) {
	decoded := &models.DecodedPML{
		Policies: []models.DecodedPolicy{
			{
				Policy: models.Policy{
					Subject: "webapp",
					Object:  "/var/www/html",
					Action:  "read",
					Effect:  "allow",
				},
			},
		},
	}

	gen := compiler.NewGenerator(decoded, "webapp")
	policy, err := gen.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if policy.ModuleName != "webapp" {
		t.Errorf("Expected module name 'webapp', got '%s'", policy.ModuleName)
	}

	if len(policy.Types) == 0 {
		t.Error("Expected types to be generated")
	}

	if len(policy.Rules) == 0 {
		t.Error("Expected rules to be generated")
	}
}
