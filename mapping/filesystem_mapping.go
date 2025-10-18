package mapping

import (
	"fmt"
	"strings"

	"github.com/cici0602/pml-to-selinux/models"
)

// FilesystemMapper handles mapping of filesystem contexts
type FilesystemMapper struct {
	levelMapper *LevelMapper
}

// NewFilesystemMapper creates a new FilesystemMapper
func NewFilesystemMapper(levelMapper *LevelMapper) *FilesystemMapper {
	return &FilesystemMapper{
		levelMapper: levelMapper,
	}
}

// GenfsconRule represents a genfscon rule for generic filesystem contexts
// Format: genfscon <fstype> <path> <context>
// Example: genfscon proc /cpuinfo system_u:object_r:proc_cpuinfo_t:s0
type GenfsconRule struct {
	FSType  string // Filesystem type: proc, selinuxfs, sysfs, etc.
	Path    string // Path within the filesystem
	Context string // Full SELinux context
}

// FsuseRule represents a fsuse rule for filesystem usage
// Format: fs_use_<type> <fstype> <context>
// Example: fs_use_trans devpts system_u:object_r:devpts_t:s0
type FsuseRule struct {
	UseType string // trans, task, or xattr
	FSType  string // Filesystem type: ext4, xfs, tmpfs, etc.
	Context string // Default context for the filesystem
}

// PortconRule represents a portcon rule for network port contexts
// Format: portcon <protocol> <port> <context>
// Example: portcon tcp 80 system_u:object_r:http_port_t:s0
type PortconRule struct {
	Protocol string // tcp or udp
	Port     int    // Port number or port range start
	PortEnd  int    // Port range end (0 if single port)
	Context  string // SELinux context
}

// NetifconRule represents a netifcon rule for network interface contexts
// Format: netifcon <interface> <if_context> <packet_context>
// Example: netifcon eth0 system_u:object_r:netif_t:s0 system_u:object_r:netif_t:s0
type NetifconRule struct {
	Interface     string // Network interface name
	IfContext     string // Context for the interface itself
	PacketContext string // Context for packets on this interface
}

// GenerateGenfsconRules generates genfscon rules for common pseudo-filesystems
func (fm *FilesystemMapper) GenerateGenfsconRules() []GenfsconRule {
	rules := []GenfsconRule{
		// proc filesystem
		{
			FSType:  "proc",
			Path:    "/",
			Context: "system_u:object_r:proc_t:s0",
		},
		{
			FSType:  "proc",
			Path:    "/cpuinfo",
			Context: "system_u:object_r:proc_cpuinfo_t:s0",
		},
		{
			FSType:  "proc",
			Path:    "/meminfo",
			Context: "system_u:object_r:proc_meminfo_t:s0",
		},
		{
			FSType:  "proc",
			Path:    "/kcore",
			Context: "system_u:object_r:proc_kcore_t:s0",
		},
		{
			FSType:  "proc",
			Path:    "/kmsg",
			Context: "system_u:object_r:proc_kmsg_t:s0",
		},
		{
			FSType:  "proc",
			Path:    "/sys",
			Context: "system_u:object_r:sysctl_t:s0",
		},

		// sysfs filesystem
		{
			FSType:  "sysfs",
			Path:    "/",
			Context: "system_u:object_r:sysfs_t:s0",
		},
		{
			FSType:  "sysfs",
			Path:    "/devices",
			Context: "system_u:object_r:device_t:s0",
		},

		// selinuxfs
		{
			FSType:  "selinuxfs",
			Path:    "/",
			Context: "system_u:object_r:security_t:s0",
		},

		// tmpfs
		{
			FSType:  "tmpfs",
			Path:    "/",
			Context: "system_u:object_r:tmpfs_t:s0",
		},

		// devpts
		{
			FSType:  "devpts",
			Path:    "/",
			Context: "system_u:object_r:devpts_t:s0",
		},
	}

	return rules
}

// GenerateFsuseRules generates fs_use rules for different filesystem types
func (fm *FilesystemMapper) GenerateFsuseRules() []FsuseRule {
	rules := []FsuseRule{
		// Extended attribute filesystems (support SELinux labels)
		{
			UseType: "xattr",
			FSType:  "ext2",
			Context: "system_u:object_r:fs_t:s0",
		},
		{
			UseType: "xattr",
			FSType:  "ext3",
			Context: "system_u:object_r:fs_t:s0",
		},
		{
			UseType: "xattr",
			FSType:  "ext4",
			Context: "system_u:object_r:fs_t:s0",
		},
		{
			UseType: "xattr",
			FSType:  "xfs",
			Context: "system_u:object_r:fs_t:s0",
		},
		{
			UseType: "xattr",
			FSType:  "btrfs",
			Context: "system_u:object_r:fs_t:s0",
		},
		{
			UseType: "xattr",
			FSType:  "jfs",
			Context: "system_u:object_r:fs_t:s0",
		},

		// Transition filesystems (context from creating process)
		{
			UseType: "trans",
			FSType:  "tmpfs",
			Context: "system_u:object_r:tmpfs_t:s0",
		},
		{
			UseType: "trans",
			FSType:  "devpts",
			Context: "system_u:object_r:devpts_t:s0",
		},
		{
			UseType: "trans",
			FSType:  "mqueue",
			Context: "system_u:object_r:mqueue_spool_t:s0",
		},
		{
			UseType: "trans",
			FSType:  "pipefs",
			Context: "system_u:object_r:fs_t:s0",
		},
		{
			UseType: "trans",
			FSType:  "sockfs",
			Context: "system_u:object_r:fs_t:s0",
		},

		// Task filesystems (context based on task)
		{
			UseType: "task",
			FSType:  "proc",
			Context: "system_u:object_r:proc_t:s0",
		},
		{
			UseType: "task",
			FSType:  "sysfs",
			Context: "system_u:object_r:sysfs_t:s0",
		},
	}

	return rules
}

// InferFSType infers filesystem type from mount point or path
func (fm *FilesystemMapper) InferFSType(path string) string {
	path = strings.ToLower(path)

	switch {
	case strings.HasPrefix(path, "/selinux"), strings.HasPrefix(path, "/sys/fs/selinux"):
		return "selinuxfs"
	case strings.HasPrefix(path, "/proc"):
		return "proc"
	case strings.HasPrefix(path, "/sys"):
		return "sysfs"
	case strings.HasPrefix(path, "/dev/pts"):
		return "devpts"
	case strings.HasPrefix(path, "/dev/shm"), strings.HasPrefix(path, "/run"), strings.HasPrefix(path, "/tmp"):
		return "tmpfs"
	default:
		// Default to xattr-supporting filesystem
		return "ext4"
	}
}

// GenerateFilesystemContext generates a complete filesystem context
func (fm *FilesystemMapper) GenerateFilesystemContext(fsType, path, typeName string, level models.SecurityRange) string {
	return fmt.Sprintf("system_u:object_r:%s:%s", typeName, level.String())
}

// GetFilesystemSecurity returns security properties for a filesystem type
type FilesystemSecurity struct {
	SupportsXattr   bool   // Supports extended attributes
	SupportsLabels  bool   // Supports SELinux labels
	DefaultUseType  string // Default fs_use type
	SecurityLevel   string // Default security level
	RecommendedType string // Recommended SELinux type
}

// GetFilesystemSecurity returns security properties for different filesystem types
func (fm *FilesystemMapper) GetFilesystemSecurity(fsType string) FilesystemSecurity {
	fsType = strings.ToLower(fsType)

	switch fsType {
	case "ext2", "ext3", "ext4", "xfs", "btrfs", "jfs":
		return FilesystemSecurity{
			SupportsXattr:   true,
			SupportsLabels:  true,
			DefaultUseType:  "xattr",
			SecurityLevel:   "s0",
			RecommendedType: "fs_t",
		}

	case "tmpfs", "devpts", "mqueue", "pipefs", "sockfs":
		return FilesystemSecurity{
			SupportsXattr:   false,
			SupportsLabels:  true,
			DefaultUseType:  "trans",
			SecurityLevel:   "s0",
			RecommendedType: "tmpfs_t",
		}

	case "proc":
		return FilesystemSecurity{
			SupportsXattr:   false,
			SupportsLabels:  true,
			DefaultUseType:  "task",
			SecurityLevel:   "s0",
			RecommendedType: "proc_t",
		}

	case "sysfs":
		return FilesystemSecurity{
			SupportsXattr:   false,
			SupportsLabels:  true,
			DefaultUseType:  "task",
			SecurityLevel:   "s0",
			RecommendedType: "sysfs_t",
		}

	case "selinuxfs":
		return FilesystemSecurity{
			SupportsXattr:   false,
			SupportsLabels:  true,
			DefaultUseType:  "genfs",
			SecurityLevel:   "s0",
			RecommendedType: "security_t",
		}

	case "nfs", "nfs4", "cifs", "smb":
		return FilesystemSecurity{
			SupportsXattr:   false,
			SupportsLabels:  false,
			DefaultUseType:  "trans",
			SecurityLevel:   "s0",
			RecommendedType: "nfs_t",
		}

	default:
		return FilesystemSecurity{
			SupportsXattr:   true,
			SupportsLabels:  true,
			DefaultUseType:  "xattr",
			SecurityLevel:   "s0",
			RecommendedType: "fs_t",
		}
	}
}

// ValidateFilesystemPolicy validates filesystem labeling policy
func (fm *FilesystemMapper) ValidateFilesystemPolicy(genfsconRules []GenfsconRule, fsuseRules []FsuseRule) []error {
	errors := []error{}

	// Check for duplicate genfscon rules
	genfsconSeen := make(map[string]bool)
	for i, rule := range genfsconRules {
		key := fmt.Sprintf("%s:%s", rule.FSType, rule.Path)
		if genfsconSeen[key] {
			errors = append(errors, fmt.Errorf("genfscon rule %d: duplicate rule for %s %s", i, rule.FSType, rule.Path))
		}
		genfsconSeen[key] = true

		// Validate context format
		if !isValidContext(rule.Context) {
			errors = append(errors, fmt.Errorf("genfscon rule %d: invalid context format: %s", i, rule.Context))
		}
	}

	// Check for duplicate fsuse rules
	fsuseSeen := make(map[string]bool)
	for i, rule := range fsuseRules {
		key := rule.FSType
		if fsuseSeen[key] {
			errors = append(errors, fmt.Errorf("fsuse rule %d: duplicate rule for filesystem %s", i, rule.FSType))
		}
		fsuseSeen[key] = true

		// Validate use type
		if rule.UseType != "xattr" && rule.UseType != "trans" && rule.UseType != "task" {
			errors = append(errors, fmt.Errorf("fsuse rule %d: invalid use type: %s", i, rule.UseType))
		}

		// Validate context format
		if !isValidContext(rule.Context) {
			errors = append(errors, fmt.Errorf("fsuse rule %d: invalid context format: %s", i, rule.Context))
		}
	}

	return errors
}

// isValidContext checks if a context string is valid
// Basic validation: user:role:type:level
func isValidContext(context string) bool {
	parts := strings.Split(context, ":")
	return len(parts) == 4 && parts[0] != "" && parts[1] != "" && parts[2] != "" && parts[3] != ""
}

// GeneratePortconRules generates portcon rules for common network ports
func (fm *FilesystemMapper) GeneratePortconRules() []PortconRule {
	rules := []PortconRule{
		// HTTP/HTTPS
		{Protocol: "tcp", Port: 80, Context: "system_u:object_r:http_port_t:s0"},
		{Protocol: "tcp", Port: 443, Context: "system_u:object_r:http_port_t:s0"},
		{Protocol: "tcp", Port: 8080, Context: "system_u:object_r:http_port_t:s0"},

		// SSH
		{Protocol: "tcp", Port: 22, Context: "system_u:object_r:ssh_port_t:s0"},

		// DNS
		{Protocol: "tcp", Port: 53, Context: "system_u:object_r:dns_port_t:s0"},
		{Protocol: "udp", Port: 53, Context: "system_u:object_r:dns_port_t:s0"},

		// SMTP
		{Protocol: "tcp", Port: 25, Context: "system_u:object_r:smtp_port_t:s0"},
		{Protocol: "tcp", Port: 587, Context: "system_u:object_r:smtp_port_t:s0"},

		// FTP
		{Protocol: "tcp", Port: 20, Context: "system_u:object_r:ftp_data_port_t:s0"},
		{Protocol: "tcp", Port: 21, Context: "system_u:object_r:ftp_port_t:s0"},

		// Database ports
		{Protocol: "tcp", Port: 3306, Context: "system_u:object_r:mysqld_port_t:s0"},
		{Protocol: "tcp", Port: 5432, Context: "system_u:object_r:postgresql_port_t:s0"},
	}

	return rules
}
