package mapping

import (
	"fmt"
	"strings"

	"github.com/cici0602/pml-to-selinux/models"
)

// LevelMapper handles mapping of security levels from PML to SELinux MLS/MCS
type LevelMapper struct {
	// levelMap maps PML level names to SELinux security levels
	levelMap map[string]models.SecurityLevel

	// categoryMap maps PML category names to category numbers
	categoryMap map[string]int

	// Default levels for common security classifications
	defaultLevels map[string]models.SecurityLevel
}

// NewLevelMapper creates a new LevelMapper with default mappings
func NewLevelMapper() *LevelMapper {
	lm := &LevelMapper{
		levelMap:    make(map[string]models.SecurityLevel),
		categoryMap: make(map[string]int),
		defaultLevels: map[string]models.SecurityLevel{
			"public":       models.NewSecurityLevel(0),
			"unclassified": models.NewSecurityLevel(0),
			"internal":     models.NewSecurityLevel(1),
			"confidential": models.NewSecurityLevel(2),
			"secret":       models.NewSecurityLevel(3),
			"top_secret":   models.NewSecurityLevel(4),
		},
	}

	// Initialize common category mappings
	lm.initDefaultCategories()

	return lm
}

// initDefaultCategories initializes default category mappings
func (lm *LevelMapper) initDefaultCategories() {
	categories := map[string]int{
		"hr":        0,  // Human Resources
		"finance":   1,  // Financial data
		"legal":     2,  // Legal documents
		"technical": 3,  // Technical information
		"medical":   4,  // Medical records
		"pii":       5,  // Personally Identifiable Information
		"pci":       6,  // Payment Card Industry data
		"phi":       7,  // Protected Health Information
		"itar":      8,  // International Traffic in Arms Regulations
		"export":    9,  // Export controlled
		"research":  10, // Research data
		"dev":       11, // Development
		"staging":   12, // Staging environment
		"prod":      13, // Production environment
	}

	for name, num := range categories {
		lm.categoryMap[name] = num
	}
}

// RegisterLevel registers a custom level mapping
func (lm *LevelMapper) RegisterLevel(name string, level models.SecurityLevel) error {
	if !level.IsValid() {
		return fmt.Errorf("invalid security level for %s", name)
	}
	lm.levelMap[name] = level
	return nil
}

// RegisterCategory registers a custom category mapping
func (lm *LevelMapper) RegisterCategory(name string, categoryNum int) error {
	if categoryNum < 0 || categoryNum > 1023 {
		return fmt.Errorf("category number out of range: %d", categoryNum)
	}
	lm.categoryMap[name] = categoryNum
	return nil
}

// MapLevel maps a PML level description to a SELinux security level
// Supports formats like:
//   - "secret" -> s3
//   - "confidential:hr,finance" -> s2:c0,c1
//   - "top_secret:c0.c255" -> s4:c0.c255
func (lm *LevelMapper) MapLevel(levelDesc string) (models.SecurityLevel, error) {
	levelDesc = strings.TrimSpace(levelDesc)
	if levelDesc == "" {
		return models.DefaultSecurityLevel(), nil
	}

	parts := strings.Split(levelDesc, ":")
	baseName := parts[0]

	// Try to parse as direct SELinux format first (s0, s1:c0, etc.)
	// Check if it's a valid SELinux format: s followed by digit
	if strings.HasPrefix(baseName, "s") && len(baseName) > 1 && baseName[1] >= '0' && baseName[1] <= '9' {
		return models.ParseSecurityLevel(levelDesc)
	}

	// Look up base level from name
	baseLevel, ok := lm.levelMap[baseName]
	if !ok {
		// Try default levels
		baseLevel, ok = lm.defaultLevels[baseName]
		if !ok {
			return models.SecurityLevel{}, fmt.Errorf("unknown level: %s", baseName)
		}
	}

	// If no categories specified, return base level
	if len(parts) == 1 {
		return baseLevel, nil
	}

	// Parse categories
	categories, err := lm.parseCategories(parts[1])
	if err != nil {
		return models.SecurityLevel{}, fmt.Errorf("invalid categories: %w", err)
	}

	return models.SecurityLevel{
		Sensitivity: baseLevel.Sensitivity,
		Categories:  categories,
	}, nil
}

// MapRange maps a PML level range to a SELinux security range
// Supports formats like:
//   - "secret" -> s3
//   - "confidential-secret" -> s2-s3
//   - "internal:hr-secret:hr,finance" -> s1:c0-s3:c0,c1
func (lm *LevelMapper) MapRange(rangeDesc string) (models.SecurityRange, error) {
	rangeDesc = strings.TrimSpace(rangeDesc)
	if rangeDesc == "" {
		return models.DefaultSecurityRange(), nil
	}

	// Try to parse as direct SELinux format first
	// Check if it's a valid SELinux format: s followed by digit
	if strings.HasPrefix(rangeDesc, "s") && len(rangeDesc) > 1 && rangeDesc[1] >= '0' && rangeDesc[1] <= '9' {
		return models.ParseSecurityRange(rangeDesc)
	}

	// Parse range components
	parts := strings.Split(rangeDesc, "-")
	if len(parts) == 0 || len(parts) > 2 {
		return models.SecurityRange{}, fmt.Errorf("invalid range format: %s", rangeDesc)
	}

	lowLevel, err := lm.MapLevel(parts[0])
	if err != nil {
		return models.SecurityRange{}, fmt.Errorf("invalid low level: %w", err)
	}

	highLevel := lowLevel
	if len(parts) == 2 {
		highLevel, err = lm.MapLevel(parts[1])
		if err != nil {
			return models.SecurityRange{}, fmt.Errorf("invalid high level: %w", err)
		}
	}

	sr := models.SecurityRange{Low: lowLevel, High: highLevel}
	if !sr.IsValid() {
		return models.SecurityRange{}, fmt.Errorf("invalid security range")
	}

	return sr, nil
}

// parseCategories parses category specifications
// Supports:
//   - Named categories: "hr,finance" -> [0, 1]
//   - Numeric categories: "c0,c5" -> [0, 5]
//   - Ranges: "c0.c10" -> [0, 1, 2, ..., 10]
func (lm *LevelMapper) parseCategories(catSpec string) ([]int, error) {
	catSpec = strings.TrimSpace(catSpec)
	if catSpec == "" {
		return []int{}, nil
	}

	// If it looks like SELinux format (starts with 'c'), parse directly
	if strings.HasPrefix(catSpec, "c") {
		level, err := models.ParseSecurityLevel("s0:" + catSpec)
		if err != nil {
			return nil, err
		}
		return level.Categories, nil
	}

	// Parse named categories
	parts := strings.Split(catSpec, ",")
	categories := make([]int, 0, len(parts))
	seen := make(map[int]bool)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		catNum, ok := lm.categoryMap[part]
		if !ok {
			return nil, fmt.Errorf("unknown category: %s", part)
		}
		if !seen[catNum] {
			categories = append(categories, catNum)
			seen[catNum] = true
		}
	}

	// Sort categories
	for i := 0; i < len(categories); i++ {
		for j := i + 1; j < len(categories); j++ {
			if categories[i] > categories[j] {
				categories[i], categories[j] = categories[j], categories[i]
			}
		}
	}

	return categories, nil
}

// InferLevelFromPath infers security level from file path
// Uses heuristics to determine appropriate security level
func (lm *LevelMapper) InferLevelFromPath(path string) models.SecurityLevel {
	path = strings.ToLower(path)

	// Top secret paths
	if strings.Contains(path, "top_secret") ||
		strings.Contains(path, "topsecret") ||
		strings.Contains(path, "classified") {
		return lm.defaultLevels["top_secret"]
	}

	// Secret paths
	if strings.Contains(path, "secret") ||
		strings.Contains(path, "/secure/") {
		return lm.defaultLevels["secret"]
	}

	// Confidential paths
	if strings.Contains(path, "confidential") ||
		strings.Contains(path, "private") ||
		strings.Contains(path, "/restricted/") {
		return lm.defaultLevels["confidential"]
	}

	// Internal paths
	if strings.Contains(path, "internal") {
		return lm.defaultLevels["internal"]
	}

	// Default to public
	return lm.defaultLevels["public"]
}

// InferCategoriesFromPath infers categories from file path
func (lm *LevelMapper) InferCategoriesFromPath(path string) []int {
	path = strings.ToLower(path)
	categories := []int{}
	seen := make(map[int]bool)

	// Check for category keywords in path
	for name, num := range lm.categoryMap {
		if strings.Contains(path, name) && !seen[num] {
			categories = append(categories, num)
			seen[num] = true
		}
	}

	// Sort categories
	for i := 0; i < len(categories); i++ {
		for j := i + 1; j < len(categories); j++ {
			if categories[i] > categories[j] {
				categories[i], categories[j] = categories[j], categories[i]
			}
		}
	}

	return categories
}

// GenerateMLSConstraints generates MLS constraint rules
func (lm *LevelMapper) GenerateMLSConstraints() []models.MLSConstraint {
	constraints := []models.MLSConstraint{
		// Read-down: Can read objects at same or lower sensitivity
		{
			Classes:     []string{"file", "dir", "lnk_file"},
			Permissions: []string{"read", "getattr", "open"},
			Expression:  "l1 dom l2",
		},
		// Write-up: Can write to objects at same or higher sensitivity
		{
			Classes:     []string{"file", "dir"},
			Permissions: []string{"write", "append", "create"},
			Expression:  "l2 dom l1",
		},
		// No read-up
		{
			Classes:     []string{"file"},
			Permissions: []string{"read"},
			Expression:  "not (l2 dom l1 and l1 != l2)",
		},
		// No write-down
		{
			Classes:     []string{"file"},
			Permissions: []string{"write"},
			Expression:  "not (l1 dom l2 and l1 != l2)",
		},
	}

	return constraints
}

// ValidateMLSPolicy validates MLS policy consistency
func (lm *LevelMapper) ValidateMLSPolicy(contexts []models.MLSContext) []error {
	errors := []error{}

	for i, ctx := range contexts {
		// Validate level
		if !ctx.Level.IsValid() {
			errors = append(errors, fmt.Errorf("context %d: invalid security range: %s", i, ctx.Level.String()))
		}

		// Check for write-up violations (simplified check)
		// In real implementation, would check against policy rules
	}

	return errors
}

// GetLevelName returns the human-readable name for a sensitivity level
func (lm *LevelMapper) GetLevelName(sensitivity int) string {
	for name, level := range lm.defaultLevels {
		if level.Sensitivity == sensitivity {
			return name
		}
	}
	return fmt.Sprintf("s%d", sensitivity)
}

// GetCategoryName returns the human-readable name for a category
func (lm *LevelMapper) GetCategoryName(categoryNum int) string {
	for name, num := range lm.categoryMap {
		if num == categoryNum {
			return name
		}
	}
	return fmt.Sprintf("c%d", categoryNum)
}
