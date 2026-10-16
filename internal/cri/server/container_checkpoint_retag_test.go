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
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CVE-2026-50195: CRImportCheckpoint used to re-tag the checkpoint's base image
// with the NAME:TAG recorded inside the checkpoint archive
// (tagImage.Name = config.RootfsImageName followed by ImageService().Create),
// which let a crafted archive rebind an arbitrary local NAME:TAG onto an image
// of the attacker's choosing. The fix removes that image-store write.
//
// CRImportCheckpoint cannot be driven from a unit test — criService.client is a
// concrete *containerd.Client, so it needs a live daemon, a populated image
// store and a real checkpoint archive; upstream ships no test with the fix for
// the same reason. The property the fix establishes is therefore asserted on
// the restore path itself: no mutation of the image store may be reachable from
// it, so a future re-introduction of the re-tag block fails here.

const checkpointRestoreSourceFile = "container_checkpoint_linux.go"

// imageStoreMutators are the mutating methods of the image store service
// (github.com/containerd/containerd/v2/core/images.Store). Reads (Get, List)
// are unaffected by this CVE and are still used by the restore path.
var imageStoreMutators = map[string]bool{
	"Create": true,
	"Update": true,
	"Delete": true,
}

// crImportCheckpointDecl parses the restore path's source file and returns the
// CRImportCheckpoint declaration together with the fileset needed to render it.
func crImportCheckpointDecl(t *testing.T) (*token.FileSet, *ast.FuncDecl) {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, checkpointRestoreSourceFile, nil, 0)
	require.NoError(t, err, "failed to parse %s", checkpointRestoreSourceFile)

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "CRImportCheckpoint" && fn.Body != nil {
			return fset, fn
		}
	}

	t.Fatalf("CRImportCheckpoint not found in %s", checkpointRestoreSourceFile)
	return nil, nil
}

func render(t *testing.T, fset *token.FileSet, node ast.Node) string {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, printer.Fprint(&buf, fset, node))
	return buf.String()
}

func TestCRImportCheckpointDoesNotWriteToImageStore(t *testing.T) {
	fset, fn := crImportCheckpointDecl(t)

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !imageStoreMutators[sel.Sel.Name] {
			return true
		}
		if strings.Contains(render(t, fset, sel.X), "ImageService()") {
			t.Errorf(
				"CRImportCheckpoint mutates the image store at %s: %s\n"+
					"restoring a checkpoint must never write to the image store (CVE-2026-50195)",
				fset.Position(call.Pos()), render(t, fset, call),
			)
		}
		return true
	})
}

func TestCRImportCheckpointDoesNotReuseArchiveImageName(t *testing.T) {
	fset, fn := crImportCheckpointDecl(t)

	// The removed re-tag block copied the archive-supplied image name onto an
	// image record (tagImage.Name = config.RootfsImageName) before storing it.
	// The name may still be validated and reported, never assigned.
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, rhs := range assign.Rhs {
			if render(t, fset, rhs) == "config.RootfsImageName" {
				t.Errorf(
					"CRImportCheckpoint assigns the archive-supplied image name at %s: %s\n"+
						"the checkpoint's NAME:TAG must not be re-applied to a local image (CVE-2026-50195)",
					fset.Position(assign.Pos()), render(t, fset, assign),
				)
			}
		}
		return true
	})
}

func TestCRImportCheckpointValidatesRootfsImageName(t *testing.T) {
	fset, fn := crImportCheckpointDecl(t)

	// The reference validation sits directly above the removed block and is
	// deliberately retained: dropping the re-tag must not also drop the check
	// that rejects a malformed NAME:TAG coming out of the archive.
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if render(t, fset, call.Fun) != "reference.ParseAnyReference" {
			return true
		}
		if len(call.Args) == 1 && render(t, fset, call.Args[0]) == "config.RootfsImageName" {
			found = true
		}
		return true
	})

	assert.True(t, found,
		"CRImportCheckpoint no longer validates config.RootfsImageName with reference.ParseAnyReference")
}
