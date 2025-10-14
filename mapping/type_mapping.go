package mapping

import (
	"fmt"
	"path/filepath"
	"strings"
)

// TypeMapper handles conversion from paths to SELinux type names
type TypeMapper struct {
	// Module name prefix for generated types
	modulePrefix string
	// Custom path-to-type mappings
	customMappings map[string]string
}

// NewTypeMapper creates a new TypeMapper instance
func NewTypeMapper(modulePrefix string) *TypeMapper {
	return &TypeMapper{
		modulePrefix:   modulePrefix,
		customMappings: make(map[string]string),
	}
}

// AddCustomMapping adds a custom path-to-type mapping
func (tm *TypeMapper) AddCustomMapping(path, typeName string) {
	tm.customMappings[path] = typeName
}

// PathToType converts a path pattern to a SELinux type name
// Examples:
//
//	/var/www/*       →  httpd_var_www_t
//	/var/log/httpd/* →  httpd_var_log_httpd_t
//	/etc/httpd/*     →  httpd_etc_httpd_t
func (tm *TypeMapper) PathToType(path string) string {
	// Check for custom mapping first
	if customType, ok := tm.customMappings[path]; ok {
		return customType
	}

	// Extract base path without wildcards
	basePath := ExtractBasePath(path)

	// Normalize the path
	basePath = NormalizePath(basePath)

	// Remove leading slash and convert to type name
	typeName := strings.TrimPrefix(basePath, "/")

	// Replace slashes with underscores
	typeName = strings.ReplaceAll(typeName, "/", "_")

	// Replace dashes with underscores
	typeName = strings.ReplaceAll(typeName, "-", "_")

	// Remove any dots (for file extensions)
	typeName = strings.ReplaceAll(typeName, ".", "_")

	// Clean up any double underscores
	for strings.Contains(typeName, "__") {
		typeName = strings.ReplaceAll(typeName, "__", "_")
	}

	// Add module prefix and _t suffix
	if tm.modulePrefix != "" {
		// Sanitize the module prefix as well
		sanitizedPrefix := strings.ReplaceAll(tm.modulePrefix, "-", "_")
		if !strings.HasPrefix(typeName, sanitizedPrefix+"_") {
			typeName = sanitizedPrefix + "_" + typeName
		}
	}

	// Ensure it ends with _t
	if !strings.HasSuffix(typeName, "_t") {
		typeName = typeName + "_t"
	}

	return typeName
}

// InferTypeCategory infers the SELinux type category/attribute based on the path
// Returns suggested attributes for the type
func (tm *TypeMapper) InferTypeCategory(path string) []string {
	attributes := make([]string, 0)

	// Check path patterns to determine attributes
	if strings.Contains(path, "/bin") || strings.Contains(path, "/sbin") {
		attributes = append(attributes, "exec_type")
	}

	if strings.Contains(path, "/lib") {
		attributes = append(attributes, "lib_type")
	}

	if strings.Contains(path, "/var/log") || strings.HasSuffix(path, ".log") {
		attributes = append(attributes, "logfile")
	}

	if strings.Contains(path, "/etc") || strings.HasSuffix(path, ".conf") || strings.HasSuffix(path, ".cfg") {
		attributes = append(attributes, "configfile")
	}

	if strings.Contains(path, "/var/run") || strings.Contains(path, "/run") {
		attributes = append(attributes, "pidfile")
	}

	if strings.Contains(path, "/tmp") || strings.Contains(path, "/var/tmp") {
		attributes = append(attributes, "tmpfile")
	}

	if strings.Contains(path, "/var/www") || strings.Contains(path, "/srv") {
		attributes = append(attributes, "httpdcontent")
	}

	// Always add file_type for non-domain types
	if !contains(attributes, "exec_type") {
		attributes = append(attributes, "file_type")
	}

	return attributes
}

// SubjectToType converts a subject (domain) name to proper type format
// Ensures the subject name ends with _t and follows naming conventions
func (tm *TypeMapper) SubjectToType(subject string) string {
	// If already ends with _t, return as is
	if strings.HasSuffix(subject, "_t") {
		return subject
	}

	// Add _t suffix
	return subject + "_t"
}

// GenerateTypeDescription generates a human-readable description for a type
func (tm *TypeMapper) GenerateTypeDescription(typeName, path string) string {
	// Extract the main component from the type name
	base := strings.TrimSuffix(typeName, "_t")
	if tm.modulePrefix != "" {
		base = strings.TrimPrefix(base, tm.modulePrefix+"_")
	}

	// Clean up the base name for display
	displayName := strings.ReplaceAll(base, "_", " ")

	// Generate description based on path patterns
	if strings.Contains(path, "/var/log") {
		return fmt.Sprintf("Log files for %s", displayName)
	}

	if strings.Contains(path, "/etc") {
		return fmt.Sprintf("Configuration files for %s", displayName)
	}

	if strings.Contains(path, "/var/www") || strings.Contains(path, "/srv") {
		return fmt.Sprintf("Web content for %s", displayName)
	}

	if strings.Contains(path, "/var/run") || strings.Contains(path, "/run") {
		return fmt.Sprintf("Runtime files for %s", displayName)
	}

	return fmt.Sprintf("Files in %s", path)
}

// IsSystemPath checks if a path is a system path that should use system types
func IsSystemPath(path string) bool {
	systemPaths := []string{
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/lib",
		"/lib64",
		"/usr/lib",
		"/usr/lib64",
	}

	for _, sysPath := range systemPaths {
		if strings.HasPrefix(path, sysPath) {
			return true
		}
	}

	return false
}

// GetSystemType returns the appropriate system type for a system path
func GetSystemType(path string) string {
	if strings.Contains(path, "/bin") || strings.Contains(path, "/sbin") {
		return "bin_t"
	}

	if strings.Contains(path, "/lib") {
		return "lib_t"
	}

	return "system_t"
}

// SanitizeTypeName ensures a type name follows SELinux naming conventions
func SanitizeTypeName(name string) string {
	// Convert to lowercase
	name = strings.ToLower(name)

	// Replace invalid characters with underscores
	invalidChars := []string{"-", ".", " ", "/", "\\"}
	for _, char := range invalidChars {
		name = strings.ReplaceAll(name, char, "_")
	}

	// Remove leading/trailing underscores
	name = strings.Trim(name, "_")

	// Clean up double underscores
	for strings.Contains(name, "__") {
		name = strings.ReplaceAll(name, "__", "_")
	}

	// Ensure it doesn't start with a number
	if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
		name = "t_" + name
	}

	return name
}

// contains checks if a string slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetRelativePath gets relative path for display purposes
func GetRelativePath(fullPath, basePath string) string {
	rel, err := filepath.Rel(basePath, fullPath)
	if err != nil {
		return fullPath
	}
	return rel
}
