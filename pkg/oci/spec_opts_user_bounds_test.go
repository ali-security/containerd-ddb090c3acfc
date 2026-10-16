//go:build !windows

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

package oci

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/moby/sys/user"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"

	"github.com/containerd/containerd/v2/core/containers"
)

// getSupplementalGroupsFromPath resolves supplemental groups from the
// /etc/group file of the rootfs at root, confining the lookup to root the
// same way GIDFromPath and UserFromPath do.
func getSupplementalGroupsFromPath(root string, filter func(user.Group) bool) ([]uint32, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return getSupplementalGroupsFromFS(r.FS(), filter)
}

// TestOpenBoundedUserFileCapsReads asserts the boundary behavior of the read
// cap: well below, ending exactly at, and past maxUserFileBytes.
func TestOpenBoundedUserFileCapsReads(t *testing.T) {
	t.Parallel()

	beyond := []byte("\nbeyond:x:42:\n")

	for _, tc := range []struct {
		name     string
		padBytes int
		wantGids []uint32
		wantErr  bool
	}{
		{
			name:     "pad below cap, beyond is parsed",
			padBytes: 100,
			wantGids: []uint32{42},
		},
		{
			name:     "beyond ends exactly at cap, is parsed",
			padBytes: maxUserFileBytes - len(beyond),
			wantGids: []uint32{42},
		},
		{
			name:     "pad past cap, read errors out",
			padBytes: maxUserFileBytes,
			wantErr:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
				t.Fatal(err)
			}
			data := append(bytes.Repeat([]byte{0}, tc.padBytes), beyond...)
			if err := os.WriteFile(filepath.Join(root, "etc", "group"), data, 0o644); err != nil {
				t.Fatal(err)
			}

			gids, err := getSupplementalGroupsFromPath(root, func(g user.Group) bool {
				return g.Name == "beyond"
			})
			if tc.wantErr {
				assert.ErrorContains(t, err, "exceeds")
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantGids, gids)
		})
	}
}

// TestOpenBoundedUserFileRejectsNonRegularFiles verifies that non-regular
// files are refused before any byte is read from them.
func TestOpenBoundedUserFileRejectsNonRegularFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "etc", "group"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := getSupplementalGroupsFromPath(root, nil)
	assert.ErrorContains(t, err, "not a regular file")
}

// lookupWithTimeout runs fn and fails the test if it does not return in time,
// so that a lookup blocking on a FIFO surfaces as a failure instead of hanging
// the whole test binary.
func lookupWithTimeout(t *testing.T, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("user database lookup blocked")
		return nil
	}
}

// TestOpenBoundedUserFileLookups verifies that the exported passwd/group
// lookups used to resolve a container's USER refuse FIFOs in the rootfs
// without blocking and stop reading oversized user-database files.
func TestOpenBoundedUserFileLookups(t *testing.T) {
	t.Parallel()

	newRoot := func(t *testing.T) string {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
			t.Fatal(err)
		}
		return root
	}
	mkfifo := func(t *testing.T, root, name string) {
		if err := syscall.Mkfifo(filepath.Join(root, "etc", name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oversized := func(t *testing.T, root, name, entry string) {
		data := append(bytes.Repeat([]byte{'\n'}, maxUserFileBytes), entry...)
		if err := os.WriteFile(filepath.Join(root, "etc", name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("UserFromPath fifo passwd", func(t *testing.T) {
		t.Parallel()
		root := newRoot(t)
		mkfifo(t, root, "passwd")
		err := lookupWithTimeout(t, func() error {
			_, err := UserFromPath(root, nil)
			return err
		})
		assert.ErrorContains(t, err, "not a regular file")
	})

	t.Run("GIDFromPath fifo group", func(t *testing.T) {
		t.Parallel()
		root := newRoot(t)
		mkfifo(t, root, "group")
		err := lookupWithTimeout(t, func() error {
			_, err := GIDFromPath(root, nil)
			return err
		})
		assert.ErrorContains(t, err, "not a regular file")
	})

	t.Run("UserFromPath oversized passwd", func(t *testing.T) {
		t.Parallel()
		root := newRoot(t)
		oversized(t, root, "passwd", "beyond:x:42:42::/:/bin/sh\n")
		_, err := UserFromPath(root, func(u user.User) bool {
			return u.Name == "beyond"
		})
		assert.ErrorContains(t, err, "exceeds")
	})

	t.Run("GIDFromPath oversized group", func(t *testing.T) {
		t.Parallel()
		root := newRoot(t)
		oversized(t, root, "group", "beyond:x:42:\n")
		_, err := GIDFromPath(root, func(g user.Group) bool {
			return g.Name == "beyond"
		})
		assert.ErrorContains(t, err, "exceeds")
	})

	appendGroups := func(root string) error {
		c := containers.Container{ID: t.Name()}
		s := Spec{
			Version: specs.Version,
			Root:    &specs.Root{Path: root},
			Process: &specs.Process{},
		}
		return WithAppendAdditionalGroups("beyond")(context.Background(), nil, &c, &s)
	}

	t.Run("WithAppendAdditionalGroups fifo group", func(t *testing.T) {
		t.Parallel()
		if runtime.GOOS == "darwin" {
			t.Skip("additional groups are not supported on darwin")
		}
		root := newRoot(t)
		mkfifo(t, root, "group")
		err := lookupWithTimeout(t, func() error {
			return appendGroups(root)
		})
		assert.ErrorContains(t, err, "not a regular file")
	})

	t.Run("WithAppendAdditionalGroups oversized group", func(t *testing.T) {
		t.Parallel()
		if runtime.GOOS == "darwin" {
			t.Skip("additional groups are not supported on darwin")
		}
		root := newRoot(t)
		oversized(t, root, "group", "beyond:x:42:\n")
		assert.ErrorContains(t, appendGroups(root), "exceeds")
	})
}
