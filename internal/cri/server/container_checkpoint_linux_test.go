//go:build linux

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package server

import (
	"archive/tar"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/containerd/containerd/v2/core/sandbox"
	criconfig "github.com/containerd/containerd/v2/internal/cri/config"
	containerstore "github.com/containerd/containerd/v2/internal/cri/store/container"
	sandboxstore "github.com/containerd/containerd/v2/internal/cri/store/sandbox"
	ostesting "github.com/containerd/containerd/v2/pkg/os/testing"
	"github.com/containerd/log"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type testLogHook struct {
	mu      sync.Mutex
	entries []string
}

func (h *testLogHook) Levels() []logrus.Level {
	return []logrus.Level{logrus.WarnLevel}
}

func (h *testLogHook) Fire(entry *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, entry.Message)
	return nil
}

func TestFilterAndMergeAnnotations(t *testing.T) {
	for desc, tc := range map[string]struct {
		checkpointAnnotations map[string]string
		createAnnotations     map[string]string
		expectedAnnotations   map[string]string
		expectedWarnings      []string
	}{
		"cdi denied prefix boundaries": {
			checkpointAnnotations: map[string]string{
				"cdi.k8s.io/device":   "gpu",
				"cdi.k8s.io/":         "true",
				"cdi.k8s.io":          "true",
				"safe.org/cdi.k8s.io": "ignored",
				"other":               "val",
			},
			expectedAnnotations: map[string]string{
				"safe.org/cdi.k8s.io": "ignored",
				"other":               "val",
			},
			expectedWarnings: []string{
				`Denying annotation "cdi.k8s.io/device" in checkpoint restore`,
				`Denying annotation "cdi.k8s.io/" in checkpoint restore`,
				`Denying annotation "cdi.k8s.io" in checkpoint restore`,
			},
		},

		"createAnnotations update kubernetes metadata if present in both": {
			checkpointAnnotations: map[string]string{
				"io.kubernetes.container.hash":         "old-hash",
				"io.kubernetes.container.restartCount": "1",
				"safe.annotation":                      "2",
			},
			createAnnotations: map[string]string{
				"io.kubernetes.container.hash":         "new-hash",
				"io.kubernetes.container.restartCount": "2",
			},
			expectedAnnotations: map[string]string{
				"io.kubernetes.container.hash":         "new-hash",
				"io.kubernetes.container.restartCount": "2",
				"safe.annotation":                      "2",
			},
		},
	} {
		t.Run(desc, func(t *testing.T) {
			logger := logrus.New()
			logger.SetLevel(logrus.WarnLevel)
			hook := &testLogHook{}
			logger.AddHook(hook)
			ctx := log.WithLogger(context.Background(), logrus.NewEntry(logger))

			res := filterAndMergeAnnotations(
				ctx,
				tc.checkpointAnnotations,
				tc.createAnnotations,
			)

			assert.Equal(t, tc.expectedAnnotations, res)
			assert.ElementsMatch(t, tc.expectedWarnings, hook.entries)
		})
	}
}

func TestCopyNoFollowRegularFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	require.NoError(t, os.WriteFile(src, []byte("hello"), 0o644))

	require.NoError(t, copyNoFollow(src, dst, 0o600))

	data, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(data))

	info, err := os.Stat(dst)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestCopyNoFollowMissingSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "does-not-exist")
	dst := filepath.Join(dir, "dst")

	err := copyNoFollow(src, dst, 0o600)
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist), "expected ErrNotExist, got %v", err)
	assert.NoFileExists(t, dst)
}

func TestCopyNoFollowSymlinkSourceNotFollowed(t *testing.T) {
	dir := t.TempDir()

	// A stand-in for a file outside the copy that a symlink might point at.
	secret := filepath.Join(dir, "outside-target")
	require.NoError(t, os.WriteFile(secret, []byte("outside-content"), 0o600))

	src := filepath.Join(dir, "container.log")
	require.NoError(t, os.Symlink(secret, src))
	dst := filepath.Join(dir, "dst")

	err := copyNoFollow(src, dst, 0o600)
	require.Error(t, err)
	// A symlink is not a "missing file"; it must surface as an error, not be skipped.
	assert.False(t, errors.Is(err, os.ErrNotExist))
	// And the linked-to content must not have been copied into the destination.
	assert.NoFileExists(t, dst)
}

func TestCopyNoFollowRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "fifo")
	require.NoError(t, unix.Mkfifo(src, 0o600))
	dst := filepath.Join(dir, "dst")

	// Must return promptly with an error rather than blocking on the FIFO open.
	err := copyNoFollow(src, dst, 0o600)
	require.Error(t, err)
	assert.False(t, errors.Is(err, os.ErrNotExist))
	assert.NoFileExists(t, dst)
}

func TestCopyNoFollowRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "adir")
	require.NoError(t, os.Mkdir(src, 0o700))
	dst := filepath.Join(dir, "dst")

	err := copyNoFollow(src, dst, 0o600)
	require.Error(t, err)
	assert.NoFileExists(t, dst)
}

func TestAssertCheckpointDirSafe(t *testing.T) {
	t.Run("regular files and dirs allowed", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "checkpoint"), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(root, "checkpoint", "img"), []byte("x"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(root, "rootfs-diff.tar"), []byte("x"), 0o600))
		assert.NoError(t, assertCheckpointDirSafe(root))
	})

	t.Run("symlink rejected", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.Symlink("/some/outside/path", filepath.Join(root, "rootfs-diff.tar")))
		assert.Error(t, assertCheckpointDirSafe(root))
	})

	t.Run("symlink nested in subdir rejected", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "checkpoint"), 0o700))
		require.NoError(t, os.Symlink("/some/outside/path", filepath.Join(root, "checkpoint", "pages-1.img")))
		assert.Error(t, assertCheckpointDirSafe(root))
	})

	t.Run("fifo rejected", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, unix.Mkfifo(filepath.Join(root, "fifo"), 0o600))
		assert.Error(t, assertCheckpointDirSafe(root))
	})
}

func TestCheckpointArchiveEntryAllowed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		typ     byte
		allowed bool
	}{
		{"regular", tar.TypeReg, true},
		//nolint:staticcheck // TypeRegA is deprecated but external tars may still use it
		{"regular-A", tar.TypeRegA, true},
		{"directory", tar.TypeDir, true},
		{"global-header", tar.TypeXGlobalHeader, true},
		{"symlink", tar.TypeSymlink, false},
		{"hardlink", tar.TypeLink, false},
		{"char-device", tar.TypeChar, false},
		{"block-device", tar.TypeBlock, false},
		{"fifo", tar.TypeFifo, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := checkpointArchiveEntryAllowed(&tar.Header{Typeflag: tc.typ, Name: tc.name})
			assert.Equal(t, tc.allowed, got)
		})
	}
}

func TestCRImportCheckpointRestoreViaCreateDisabled(t *testing.T) {
	c := newTestCRIService()
	c.config.EnableExperimentalRestoreViaCreate = false
	_, err := c.CRImportCheckpoint(context.Background(), nil, nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "checkpoint restore via CreateContainer is disabled by configuration") {
		t.Errorf("expected error containing 'checkpoint restore via CreateContainer is disabled by configuration', got: %v", err)
	}
}

func TestCRImportCheckpointRestoreViaCreateEnabled(t *testing.T) {
	c := newTestCRIService()
	c.config.EnableExperimentalRestoreViaCreate = true
	// With the option enabled the restore path is entered and the regular
	// input validation applies.
	_, err := c.CRImportCheckpoint(context.Background(), &containerstore.Metadata{
		Config: &runtime.ContainerConfig{},
	}, nil, nil)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "disabled by configuration")
	assert.Contains(t, err.Error(), `attribute "image" missing from container definition`)
}

// readySandboxService reports every sandbox as ready so that CreateContainer
// gets past the sandbox status lookup.
type readySandboxService struct {
	fakeSandboxService
}

func (f *readySandboxService) SandboxStatus(ctx context.Context, sandboxer string, sandboxID string, verbose bool) (sandbox.ControllerStatus, error) {
	return sandbox.ControllerStatus{SandboxID: sandboxID, State: "SANDBOX_READY"}, nil
}

// createContainerFromCheckpointArchive issues a CRI CreateContainer request
// whose image is a checkpoint archive file on the host, which CreateContainer
// hands to the checkpoint restore code.
func createContainerFromCheckpointArchive(t *testing.T, c *criService) (*runtime.ContainerMetadata, *runtime.PodSandboxMetadata, error) {
	t.Helper()

	const (
		sandboxID   = "restore-sandbox-id"
		sandboxName = "restore-sandbox-name"
	)

	c.sandboxService = &readySandboxService{}
	c.os.(*ostesting.FakeOS).StatFn = os.Stat
	require.NoError(t, c.sandboxStore.Add(sandboxstore.NewSandbox(
		sandboxstore.Metadata{ID: sandboxID, Name: sandboxName},
		sandboxstore.Status{State: sandboxstore.StateReady},
	)))

	// Attacker supplied checkpoint archive on the host.
	archivePath := filepath.Join(t.TempDir(), "checkpoint.tar")
	require.NoError(t, os.WriteFile(archivePath, []byte("not a checkpoint archive"), 0o600))

	containerMetadata := &runtime.ContainerMetadata{Name: "restored"}
	sandboxMetadata := &runtime.PodSandboxMetadata{Name: "pod", Uid: "uid", Namespace: "ns"}
	_, err := c.CreateContainer(context.Background(), &runtime.CreateContainerRequest{
		PodSandboxId: sandboxID,
		Config: &runtime.ContainerConfig{
			Metadata: containerMetadata,
			Image:    &runtime.ImageSpec{Image: archivePath},
		},
		SandboxConfig: &runtime.PodSandboxConfig{Metadata: sandboxMetadata},
	})
	return containerMetadata, sandboxMetadata, err
}

// TestCreateContainerRestoreViaCreateDisabledByDefault drives the CRI
// CreateContainer entry point with a checkpoint archive as the container image.
// With the default configuration the request must be rejected before the
// archive is opened or unpacked.
func TestCreateContainerRestoreViaCreateDisabledByDefault(t *testing.T) {
	c := newTestCRIService()
	c.config.EnableExperimentalRestoreViaCreate = criconfig.DefaultRuntimeConfig().EnableExperimentalRestoreViaCreate
	require.False(t, c.config.EnableExperimentalRestoreViaCreate)

	containerMetadata, sandboxMetadata, err := createContainerFromCheckpointArchive(t, c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checkpoint restore via CreateContainer is disabled by configuration")
	assert.NotContains(t, err.Error(), "unpacking of checkpoint archive")

	// The rejected request must not leave a container behind and must release
	// the reserved container name.
	assert.Empty(t, c.containerStore.List())
	assert.NoError(t, c.containerNameIndex.Reserve(makeContainerName(containerMetadata, sandboxMetadata), "other-id"))
}

// TestCreateContainerRestoreViaCreateEnabledOpensArchive is the control for the
// test above: only when restore via CreateContainer is explicitly enabled does
// the same request reach the restore code, which opens and unpacks the archive.
func TestCreateContainerRestoreViaCreateEnabledOpensArchive(t *testing.T) {
	c := newTestCRIService()
	c.config.EnableExperimentalRestoreViaCreate = true

	_, _, err := createContainerFromCheckpointArchive(t, c)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "disabled by configuration")
	assert.Contains(t, err.Error(), "unpacking of checkpoint archive")
	assert.Empty(t, c.containerStore.List())
}
