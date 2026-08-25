package vmdetect

import (
	"context"
	"fmt"
	"time"

	internalchecks "github.com/kubev2v/vm-migration-detective/internal/checks"
	"github.com/kubev2v/vm-migration-detective/internal/persistent"
	"github.com/kubev2v/vm-migration-detective/internal/vsphere"
	"github.com/kubev2v/vm-migration-detective/pkg/checks"
	"github.com/kubev2v/vm-migration-detective/pkg/types"
	"github.com/sirupsen/logrus"
)

// Detector orchestrates VM detection operations including checks and information gathering
type Detector struct {
	inspector   persistent.InspectorInterface
	credentials Credentials
	logger      *logrus.Logger
	sslVerify   string // TLS verify option for virt-v2v-inspector vpx:// URL
}

// DetectorConfig contains configuration for creating a Detector
type DetectorConfig struct {
	// Credentials for vCenter access (required)
	Credentials Credentials
	// VDDKLibDir is the path to VDDK library directory (required, cannot be empty)
	VDDKLibDir string

	// VirtInspectorPath is the path to virt-inspector executable (optional, uses system PATH if nil)
	VirtInspectorPath *string
	// VirtV2vInspectorPath is the path to virt-v2v-inspector executable (optional, uses system PATH if nil)
	VirtV2vInspectorPath *string
	// Timeout for virt-inspector operations (optional, defaults to 30 minutes if nil)
	Timeout *time.Duration
	// Logger for logging (optional, can be nil)
	Logger *logrus.Logger
	// DB for persistent caching (optional, can be nil for memory-only caching)
	DB DB

	// V2VTimeout is retained for source compatibility with existing callers.
	// Deprecated: virt-v2v-inspector timeout and cancellation are controlled by
	// the context passed to Detect.
	V2VTimeout *time.Duration

	// SSLVerify controls TLS verification for the virt-v2v-inspector vpx:// URL
	// (e.g. "no_verify=1" or "cacert=/path/to/ca-bundle.crt").
	// Optional; defaults to "no_verify=1". Only used when a Detect call sets RunVirtV2v.
	SSLVerify *string
}

// NewDetector creates a new Detector with an internally managed inspector instance
// Returns an error if required configuration is missing or invalid
func NewDetector(config DetectorConfig) (*Detector, error) {
	// Validate required credentials
	if config.Credentials.VCenterURL == "" {
		return nil, fmt.Errorf("credentials.VCenterURL is required")
	}
	if config.Credentials.Username == "" {
		return nil, fmt.Errorf("credentials.Username is required")
	}
	if config.Credentials.Password == "" {
		return nil, fmt.Errorf("credentials.Password is required")
	}

	// Validate required VDDKLibDir
	if config.VDDKLibDir == "" {
		return nil, fmt.Errorf("VDDKLibDir is required and cannot be empty")
	}

	// Extract optional string parameters
	virtInspectorPath := ""
	if config.VirtInspectorPath != nil {
		virtInspectorPath = *config.VirtInspectorPath
	}

	virtV2vInspectorPath := ""
	if config.VirtV2vInspectorPath != nil {
		virtV2vInspectorPath = *config.VirtV2vInspectorPath
	}

	// Set default timeout if not provided
	timeout := 30 * time.Minute
	if config.Timeout != nil {
		timeout = *config.Timeout
	}

	// Create the inspector internally
	inspector := persistent.NewInspector(
		virtInspectorPath,
		virtV2vInspectorPath,
		timeout,
		config.Credentials,
		config.Logger,
		config.DB,
		config.VDDKLibDir,
	)

	sslVerify := "no_verify=1"
	if config.SSLVerify != nil {
		sslVerify = *config.SSLVerify
	}

	return &Detector{
		inspector:   inspector,
		credentials: config.Credentials,
		logger:      config.Logger,
		sslVerify:   sslVerify,
	}, nil
}

// DetectParams contains parameters for running detection
type DetectParams struct {
	Ctx           context.Context
	VMMoref       string
	SnapshotMoref string

	// RunVirtV2v, when true, runs virt-v2v-inspector as an additional
	// migration-convertibility pass after the standard virt-inspector checks.
	// Slower (full dry-run). Default false = virt-inspector only.
	RunVirtV2v bool
}

// DetectResult contains the results of detection operations
type DetectResult struct {
	// Results contains individual check results
	Results []checks.CheckResult `json:"results"`
	// AllConcerns aggregates all concerns from all checks
	AllConcerns []checks.Concern `json:"all_concerns"`
	// Passed indicates if all checks passed (no concerns found)
	Passed bool `json:"passed"`
	// OSInfo contains operating system metadata (without nested collections)
	OSInfo *OSInfo `json:"os_info,omitempty"`
	// Applications contains the list of installed applications
	Applications []types.Application `json:"applications,omitempty"`
	// Filesystems contains filesystem information
	Filesystems []types.Filesystem `json:"filesystems,omitempty"`
	// Mountpoints contains mountpoint information
	Mountpoints []types.Mountpoint `json:"mountpoints,omitempty"`
	// V2VOSInfo contains OS metadata from the virt-v2v-inspector pass.
	// Populated only when RunVirtV2v was true and the pass succeeded.
	V2VOSInfo *OSInfo `json:"v2v_os_info,omitempty"`
}

// OSInfo contains operating system metadata without nested collections
type OSInfo struct {
	Name              string `json:"name,omitempty"`
	Distro            string `json:"distro,omitempty"`
	MajorVersion      string `json:"major_version,omitempty"`
	MinorVersion      string `json:"minor_version,omitempty"`
	Architecture      string `json:"architecture,omitempty"`
	Hostname          string `json:"hostname,omitempty"`
	Product           string `json:"product,omitempty"`
	Root              string `json:"root,omitempty"`
	PackageFormat     string `json:"package_format,omitempty"`
	PackageManagement string `json:"package_management,omitempty"`
	OSInfo            string `json:"osinfo,omitempty"`
}

// CheckSelection carries optional per-run inspection toggles for the internal
// detect path. Public callers use DetectParams; this is the internal seam.
type CheckSelection struct {
	RunVirtV2v bool
}

// Detect executes validation checks on a VM snapshot
// If checkTypes is empty, all checks are run. Otherwise, only specified checks are executed.
func (r *Detector) Detect(params DetectParams, checkTypes ...checks.CheckType) (*DetectResult, error) {
	// Validate required parameters
	if params.Ctx == nil {
		return nil, fmt.Errorf("params.Ctx is required")
	}
	if params.VMMoref == "" {
		return nil, fmt.Errorf("params.VMMoref is required")
	}
	if params.SnapshotMoref == "" {
		return nil, fmt.Errorf("params.SnapshotMoref is required")
	}

	// Get snapshot disk info from vSphere
	diskInfo, err := r.getSnapshotDiskInfo(params.Ctx, params.VMMoref, params.SnapshotMoref)
	if err != nil {
		return nil, fmt.Errorf("failed to get snapshot disk info: %w", err)
	}

	return r.detectWithDiskInfo(params.Ctx, params.VMMoref, params.SnapshotMoref, diskInfo, CheckSelection{RunVirtV2v: params.RunVirtV2v}, checkTypes...)
}

// detectWithDiskInfo runs the standard checks (and, optionally, the
// virt-v2v-inspector dry-run pass) using pre-fetched disk info. It is the
// internal seam that keeps the public Detect signature unchanged while
// remaining directly testable.
//
// When RunVirtV2v is true, ONLY the virt-v2v-inspector dry-run runs — the
// standard virt-inspector and checks (fstab, disk access) are skipped because
// the two tracks are independent: separate endpoints, pools, and user actions.
func (r *Detector) detectWithDiskInfo(ctx context.Context, vmMoref, snapshotMoref string, diskInfo *types.SnapshotDiskInfo, sel CheckSelection, checkTypes ...checks.CheckType) (*DetectResult, error) {
	if sel.RunVirtV2v {
		return r.detectV2VOnly(ctx, vmMoref, snapshotMoref, diskInfo)
	}
	return r.detectStandard(ctx, vmMoref, snapshotMoref, diskInfo, checkTypes...)
}

// detectStandard runs virt-inspector and the standard checks (fstab, disk access).
func (r *Detector) detectStandard(ctx context.Context, vmMoref, snapshotMoref string, diskInfo *types.SnapshotDiskInfo, checkTypes ...checks.CheckType) (*DetectResult, error) {
	inspectorData, err := r.inspector.InspectWithVirt(ctx, vmMoref, snapshotMoref, diskInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to get inspection data: %w", err)
	}

	checksToRun := checkTypes
	if len(checksToRun) == 0 {
		checksToRun = checks.AllCheckTypes()
	}

	inspectionParams := internalchecks.InspectionParams{
		Ctx:           ctx,
		VMMoref:       vmMoref,
		SnapshotMoref: snapshotMoref,
		DiskInfo:      diskInfo,
		Inspector:     r.inspector,
	}

	results := make([]checks.CheckResult, 0, len(checksToRun))
	allConcerns := []checks.Concern{}
	allPassed := true

	for _, checkType := range checksToRun {
		var check internalchecks.Check
		var result checks.CheckResult

		switch checkType {
		case checks.CheckTypeFstab:
			check = internalchecks.NewFstabCheck()
		case checks.CheckTypeDiskAccess:
			check = internalchecks.NewDiskAccessCheck()
		default:
			continue
		}

		checkResult := check.Run(inspectionParams)
		result = checks.CheckResult{
			CheckType: checkType,
			Passed:    checkResult.Passed,
			Concerns:  checkResult.Concerns,
			Error:     checkResult.Error,
		}

		results = append(results, result)
		allConcerns = append(allConcerns, result.Concerns...)

		if !result.Passed {
			allPassed = false
		}
	}

	var osInfo *OSInfo
	var applications []types.Application
	var filesystems []types.Filesystem
	var mountpoints []types.Mountpoint

	if inspectorData != nil && len(inspectorData.Operatingsystems) > 0 {
		os := inspectorData.Operatingsystems[0]
		osInfo = &OSInfo{
			Name:              os.Name,
			Distro:            os.Distro,
			MajorVersion:      os.MajorVersion,
			MinorVersion:      os.MinorVersion,
			Architecture:      os.Architecture,
			Hostname:          os.Hostname,
			Product:           os.Product,
			Root:              os.Root,
			PackageFormat:     os.PackageFormat,
			PackageManagement: os.PackageManagement,
			OSInfo:            os.OSInfo,
		}

		if len(os.Applications.Application) > 0 {
			applications = os.Applications.Application
		}
		if len(os.Filesystems.Filesystem) > 0 {
			filesystems = os.Filesystems.Filesystem
		}
		if len(os.Mountpoints.Mountpoint) > 0 {
			mountpoints = os.Mountpoints.Mountpoint
		}
	}

	return &DetectResult{
		Results:      results,
		AllConcerns:  allConcerns,
		Passed:       allPassed,
		OSInfo:       osInfo,
		Applications: applications,
		Filesystems:  filesystems,
		Mountpoints:  mountpoints,
	}, nil
}

// detectV2VOnly runs only the virt-v2v-inspector dry-run, without the standard
// virt-inspector or checks. The two tracks are independent: v2v does not need
// virt-inspector data, and its concerns should not include standard check results.
func (r *Detector) detectV2VOnly(ctx context.Context, vmMoref, snapshotMoref string, diskInfo *types.SnapshotDiskInfo) (*DetectResult, error) {
	result := &DetectResult{Passed: true}

	v2vData, v2vErr := r.inspector.InspectWithVirtV2v(ctx, vmMoref, snapshotMoref, diskInfo, r.sslVerify)
	if v2vErr != nil {
		result.AllConcerns = append(result.AllConcerns, checks.Concern{
			ID:       "virt-v2v-dry-run-failed",
			Category: checks.ConcernCategoryWarning,
			Label:    "virt-v2v dry-run failed",
			Message:  fmt.Sprintf("virt-v2v-inspector dry-run failed: %v", v2vErr),
		})
		result.Passed = false
	} else {
		result.V2VOSInfo = osInfoFromV2V(v2vData)
	}

	return result, nil
}

// osInfoFromV2V maps the single OS in a virt-v2v-inspector result to *OSInfo.
// virt-v2v XML reports one OS (not a list) and has no hostname field.
func osInfoFromV2V(x *types.VirtV2VInspectorXML) *OSInfo {
	if x == nil {
		return nil
	}
	os := x.OS
	return &OSInfo{
		Name:              os.Name,
		Distro:            os.Distro,
		MajorVersion:      os.MajorVersion,
		MinorVersion:      os.MinorVersion,
		Architecture:      os.Arch,
		Product:           os.ProductName,
		Root:              os.Root,
		PackageFormat:     os.PackageFormat,
		PackageManagement: os.PackageManagement,
		OSInfo:            os.Osinfo,
	}
}

// getSnapshotDiskInfo queries vSphere for snapshot disk information
func (r *Detector) getSnapshotDiskInfo(ctx context.Context, vmMoref, snapshotMoref string) (*types.SnapshotDiskInfo, error) {
	// Create vSphere client
	vsphereClient, err := vsphere.NewClient(
		ctx,
		r.credentials.VCenterURL,
		r.credentials.Username,
		r.credentials.Password,
		true, // insecure - accept self-signed certificates
		r.logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to vSphere: %w", err)
	}
	defer vsphereClient.Close()

	// Get snapshot disk info
	info, err := vsphereClient.GetSnapshotDiskInfo(ctx, vmMoref, snapshotMoref)
	if err != nil {
		return nil, err
	}

	// Convert internal type to public type
	return &types.SnapshotDiskInfo{
		VMMoref:             info.VMMoref,
		VMName:              info.VMName,
		SnapshotMoref:       info.SnapshotMoref,
		DiskPaths:           nil, // Library queries these internally
		BaseDiskPaths:       nil, // Library queries these internally
		ComputeResourcePath: info.ComputeResourcePath,
	}, nil
}
