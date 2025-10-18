package mapping

import (
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

func TestLevelMapper_MapLevel(t *testing.T) {
	lm := NewLevelMapper()

	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "default level",
			input:    "",
			expected: "s0",
			wantErr:  false,
		},
		{
			name:     "public level",
			input:    "public",
			expected: "s0",
			wantErr:  false,
		},
		{
			name:     "secret level",
			input:    "secret",
			expected: "s3",
			wantErr:  false,
		},
		{
			name:     "top_secret level",
			input:    "top_secret",
			expected: "s4",
			wantErr:  false,
		},
		{
			name:     "level with categories",
			input:    "confidential:hr,finance",
			expected: "s2:c0.c1", // Two consecutive categories format as range
			wantErr:  false,
		},
		{
			name:     "direct SELinux format",
			input:    "s1:c0.c5",
			expected: "s1:c0.c5",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level, err := lm.MapLevel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("MapLevel() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && level.String() != tt.expected {
				t.Errorf("MapLevel() = %v, want %v", level.String(), tt.expected)
			}
		})
	}
}

func TestLevelMapper_MapRange(t *testing.T) {
	lm := NewLevelMapper()

	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "single level",
			input:    "secret",
			expected: "s3",
			wantErr:  false,
		},
		{
			name:     "level range",
			input:    "confidential-secret",
			expected: "s2-s3",
			wantErr:  false,
		},
		{
			name:     "direct SELinux range",
			input:    "s0:c0-s1:c0.c5",
			expected: "s0:c0-s1:c0.c5",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rang, err := lm.MapRange(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("MapRange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && rang.String() != tt.expected {
				t.Errorf("MapRange() = %v, want %v", rang.String(), tt.expected)
			}
		})
	}
}

func TestSecurityLevel_Dominates(t *testing.T) {
	tests := []struct {
		name     string
		level1   models.SecurityLevel
		level2   models.SecurityLevel
		expected bool
	}{
		{
			name:     "same level dominates",
			level1:   models.NewSecurityLevel(1),
			level2:   models.NewSecurityLevel(1),
			expected: true,
		},
		{
			name:     "higher sensitivity dominates",
			level1:   models.NewSecurityLevel(2),
			level2:   models.NewSecurityLevel(1),
			expected: true,
		},
		{
			name:     "lower sensitivity does not dominate",
			level1:   models.NewSecurityLevel(1),
			level2:   models.NewSecurityLevel(2),
			expected: false,
		},
		{
			name:     "superset categories dominates",
			level1:   models.NewSecurityLevel(1, 0, 1, 2),
			level2:   models.NewSecurityLevel(1, 0, 1),
			expected: true,
		},
		{
			name:     "subset categories does not dominate",
			level1:   models.NewSecurityLevel(1, 0),
			level2:   models.NewSecurityLevel(1, 0, 1),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.level1.Dominates(tt.level2)
			if result != tt.expected {
				t.Errorf("Dominates() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestLevelMapper_InferLevelFromPath(t *testing.T) {
	lm := NewLevelMapper()

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "top secret path",
			path:     "/var/top_secret/data",
			expected: "s4",
		},
		{
			name:     "secret path",
			path:     "/etc/secret/config",
			expected: "s3",
		},
		{
			name:     "confidential path",
			path:     "/home/user/confidential",
			expected: "s2",
		},
		{
			name:     "internal path",
			path:     "/opt/internal/app",
			expected: "s1",
		},
		{
			name:     "public path",
			path:     "/usr/share/doc",
			expected: "s0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := lm.InferLevelFromPath(tt.path)
			if level.String() != tt.expected {
				t.Errorf("InferLevelFromPath() = %v, want %v", level.String(), tt.expected)
			}
		})
	}
}

func TestLevelMapper_GenerateMLSConstraints(t *testing.T) {
	lm := NewLevelMapper()
	constraints := lm.GenerateMLSConstraints()

	if len(constraints) == 0 {
		t.Error("GenerateMLSConstraints() returned no constraints")
	}

	// Check for essential constraints
	foundReadDown := false
	foundWriteUp := false

	for _, constraint := range constraints {
		if constraint.Expression == "l1 dom l2" {
			foundReadDown = true
		}
		if constraint.Expression == "l2 dom l1" {
			foundWriteUp = true
		}
	}

	if !foundReadDown {
		t.Error("Missing read-down constraint")
	}
	if !foundWriteUp {
		t.Error("Missing write-up constraint")
	}
}

func TestParseSecurityLevel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "simple sensitivity",
			input:    "s0",
			expected: "s0",
			wantErr:  false,
		},
		{
			name:     "sensitivity with single category",
			input:    "s1:c0",
			expected: "s1:c0",
			wantErr:  false,
		},
		{
			name:     "sensitivity with category range",
			input:    "s2:c0.c5",
			expected: "s2:c0.c5",
			wantErr:  false,
		},
		{
			name:     "sensitivity with multiple categories",
			input:    "s3:c0,c2,c5",
			expected: "s3:c0,c2,c5",
			wantErr:  false,
		},
		{
			name:     "invalid format",
			input:    "invalid",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "out of range sensitivity",
			input:    "s20",
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level, err := models.ParseSecurityLevel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSecurityLevel() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && level.String() != tt.expected {
				t.Errorf("ParseSecurityLevel() = %v, want %v", level.String(), tt.expected)
			}
		})
	}
}

func TestParseSecurityRange(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "single level",
			input:    "s0",
			expected: "s0",
			wantErr:  false,
		},
		{
			name:     "simple range",
			input:    "s0-s3",
			expected: "s0-s3",
			wantErr:  false,
		},
		{
			name:     "range with categories",
			input:    "s0:c0-s3:c0.c255",
			expected: "s0:c0-s3:c0.c255",
			wantErr:  false,
		},
		{
			name:     "invalid range (low > high)",
			input:    "s3-s0",
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rang, err := models.ParseSecurityRange(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSecurityRange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && rang.String() != tt.expected {
				t.Errorf("ParseSecurityRange() = %v, want %v", rang.String(), tt.expected)
			}
		})
	}
}
