package attackpath

import "fmt"

func targetParseError(value string) error {
	return fmt.Errorf("unknown privilege target %q; use CLUSTER_ADMIN, SYSTEM_MASTERS, RBAC_CONTROL, SECRET_ACCESS, SERVICE_ACCOUNT_TAKEOVER, WORKLOAD_CONTROL, ADMISSION_CONTROL, NODE_CONTROL, HOST_ESCAPE, CLOUD_IDENTITY, CROSS_NAMESPACE_CONTROL, or PERSISTENCE", value)
}
