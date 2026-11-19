package layerdiff

import (
	"archive/tar"
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"

	"github.com/wagoodman/dive/internal/layertree"
)

// LayerInput is one image layer's own diff tree (whiteout entries retained, as stereoscope built it).
type LayerInput struct {
	Tree filetree.Reader
}

// EntryResolver returns the tar header a file was read from. *image.Image satisfies it through layertree.Header;
// tests can supply a synthetic one.
type EntryResolver interface {
	Header(ref *file.Reference) (*tar.Header, bool)
}

// Hasher returns a content hash of a regular file, or false when the content could not be read. A nil Hasher
// compares metadata only.
type Hasher func(ref *file.Reference) (uint64, bool)

// Version is one explicit appearance of a path in a layer. Appearances after a whiteout, opaque directory or
// type replacement start a new Incarnation; plain overwrites extend the current incarnation.
type Version struct {
	Incarnation int
	Layer       int
	TypeFlag    byte
	Size        int64
	Ref         *file.Reference

	// PerLayer is the status this appearance has against the version alive after the previous layer.
	PerLayer Status
	// Cumulative is the status against the first version of the same incarnation.
	Cumulative Status
	// MetadataOnly is set when a directory entry changes only its own mode/owner/xattr metadata.
	MetadataOnly bool

	metadataKey string
	hash        uint64
	hasHash     bool
}

// PathState is everything that ever happened at one path string, across all its incarnations.
type PathState struct {
	Path file.Path
	// Versions is every explicit (catalog-backed) appearance in layer order.
	Versions []*Version
	// Alive is the currently surviving version, nil when the path was removed or exists only as an implicit dir.
	Alive *Version
	// Implicit says the path is currently alive as a directory with no tar entry of its own.
	Implicit bool
	// RemovedLayers lists layers in which an incarnation closed without a same-layer re-appearance at this path.
	RemovedLayers []int
	// closures counts every incarnation end, including ones a later entry in the same layer immediately reopens.
	closures int
	// incarnation is the number the current (or next) appearance carries.
	incarnation int
	// closed says the alive incarnation ended (whiteout/opaque/type replacement), so the next appearance starts
	// the next incarnation. A plain overwrite never sets it.
	closed bool
}

// Change is one per-layer row in the report: an appearance or a removal.
type Change struct {
	Path           file.Path
	Incarnation    int
	PerLayer       Status
	Cumulative     Status
	NewIncarnation bool
	MetadataOnly   bool
	Removed        bool
}

// Totals are the image-wide byte rollups.
type Totals struct {
	// Discovered is the sum of every version's tar size.
	Discovered int64
	// Wasted is Discovered minus the sizes of the versions surviving in the final image.
	Wasted int64
	// Score is (Discovered - Wasted) / Discovered, 1.0 when nothing was discovered.
	Score float64
}

// Report is the full result of an analysis.
type Report struct {
	LayerCount int
	// Paths is every known path in first-seen order (implicit-only dirs included).
	Paths []*PathState
	// LayerChanges[i] is the changes layer i introduced, sorted by path.
	LayerChanges [][]Change
	Totals       Totals
}

// appearance is one catalog-backed or implicit entry observed in a layer's diff tree.
type appearance struct {
	path     file.Path
	ref      *file.Reference
	header   *tar.Header
	implicit bool
	node     *filenode.FileNode
}

// trieNode is one segment of an alive path. Terminal states (including implicit dirs) carry a PathState.
type trieNode struct {
	children map[string]*trieNode
	state    *PathState
}

// engine holds the streaming state; no layer tree is ever copied.
type engine struct {
	resolver EntryResolver
	hasher   Hasher

	states map[file.Path]*PathState
	order  []*PathState
	root   *trieNode

	changes [][]Change
}

// Analyze runs the diff/waste engine over the layer diff trees. It walks each tree once per layer, so its time
// is linear in the number of tar entries times average path depth, and its memory is one small PathState per
// distinct path plus the alive trie (one node per distinct directory segment).
func Analyze(layers []LayerInput, resolver EntryResolver, hasher Hasher) (*Report, error) {
	e := &engine{
		resolver: resolver,
		hasher:   hasher,
		states:   make(map[file.Path]*PathState),
		root:     &trieNode{children: make(map[string]*trieNode)},
		changes:  make([][]Change, len(layers)),
	}

	for i, layer := range layers {
		if err := e.processLayer(i, layer); err != nil {
			return nil, fmt.Errorf("layer %d: %w", i, err)
		}
	}

	report := &Report{LayerCount: len(layers), Paths: e.order, LayerChanges: e.changes}
	var discovered, alive int64
	for _, st := range e.order {
		for _, v := range st.Versions {
			discovered += v.Size
		}
		if st.Alive != nil {
			alive += st.Alive.Size
		}
	}
	wasted := discovered - alive
	report.Totals = Totals{Discovered: discovered, Wasted: wasted}
	if discovered != 0 {
		report.Totals.Score = float64(discovered-wasted) / float64(discovered)
	} else {
		report.Totals.Score = 1.0
	}
	return report, nil
}

// processLayer applies one diff tree: closures (whiteouts/opaque markers/type replacements) first, matching
// overlay semantics, then the layer's own entries in path order.
func (e *engine) processLayer(idx int, layer LayerInput) error {
	var entries []appearance
	whiteouts := make(map[file.Path]bool)
	var opaqueDirs []file.Path

	err := layertree.Walk(layer.Tree, nil, func(n *filenode.FileNode, _ bool) error {
		p := n.RealPath
		if p.IsWhiteout() {
			target, err := p.UnWhiteoutPath()
			if err != nil {
				return err
			}
			if layertree.OpaqueMarker(n) {
				opaqueDirs = append(opaqueDirs, target)
			} else {
				whiteouts[target] = true
			}
			return nil
		}
		hdr, ok := e.resolver.Header(n.Reference)
		entries = append(entries, appearance{
			path:     p,
			ref:      n.Reference,
			header:   hdr,
			implicit: !ok,
			node:     n,
		})
		return nil
	})
	if err != nil {
		return err
	}

	// entries arrive depth-first in path order from Walk; sort defensively (parents must be applied before children)
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })

	// paths the layer itself adds: a closure hitting one of these reopens an incarnation in the same layer, so it
	// gets no Removed row (the appearance row carries the new incarnation).
	reappearing := make(map[file.Path]bool, len(entries))
	for _, a := range entries {
		reappearing[a.path] = true
	}

	changes := make([]Change, 0)
	emitRemoval := func(st *PathState) {
		// an implicit-only directory has no version to close
		if st.Alive == nil {
			return
		}
		incarnation := st.Alive.Incarnation
		st.closures++
		st.Alive = nil
		st.Implicit = false
		st.closed = true
		if reappearing[st.Path] {
			return
		}
		st.RemovedLayers = append(st.RemovedLayers, idx)
		changes = append(changes, Change{
			Path:        st.Path,
			Incarnation: incarnation,
			PerLayer:    Removed,
			Cumulative:  Removed,
			Removed:     true,
		})
	}

	// phase 1: whiteouts close the target and everything beneath it
	for target := range whiteouts {
		e.closePath(target, emitRemoval)
	}
	// phase 2: opaque markers close the directory's children but keep the directory itself
	for _, dir := range opaqueDirs {
		e.closeChildren(dir, emitRemoval)
	}

	// phase 3: the layer's entries, parents first
	for _, a := range entries {
		ch, ok, err := e.applyAppearance(idx, a)
		if err != nil {
			return err
		}
		if ok {
			changes = append(changes, ch)
		}
	}

	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	e.changes[idx] = changes
	return nil
}

// applyAppearance closes the alive incarnation on a type replacement, then appends a new version (explicit
// entries) or tracks an implicit directory.
func (e *engine) applyAppearance(idx int, a appearance) (Change, bool, error) {
	st := e.stateFor(a.path)

	if a.implicit {
		// an implicit directory replacing an alive non-directory is a type replacement (e.g. a file becomes a dir
		// holding new files); the old incarnation closes, and the dir lives on without a version of its own.
		if st.Alive != nil && st.Alive.TypeFlag != tar.TypeDir {
			e.closePath(a.path, func(closed *PathState) {
				closed.closures++
				closed.closed = true
			})
		}
		// bind the state on the trie so a later replacement of this directory can close its subtree
		node := e.ensureTrie(a.path)
		if node.state == nil {
			node.state = st
		}
		if st.Alive == nil {
			st.Implicit = true
		}
		return Change{}, false, nil
	}

	hdr := a.header
	typeFlag := hdr.Typeflag

	// determine what currently lives at this path. An implicit directory is alive in the applied filesystem even
	// though it has no catalog-backed version of its own.
	var aliveType byte
	hasAlive := false
	switch {
	case st.Implicit:
		aliveType, hasAlive = tar.TypeDir, true
	case st.Alive != nil:
		aliveType, hasAlive = st.Alive.TypeFlag, true
	}

	if hasAlive && aliveType != typeFlag {
		// type replacement: a directory takes its subtree with it; a non-directory simply ends its own incarnation
		if aliveType == tar.TypeDir {
			e.closeChildren(a.path, func(closed *PathState) {
				closed.closures++
				closed.closed = true
			})
		}
		st.closures++
		st.Alive = nil
		st.Implicit = false
		st.closed = true
	}

	incarnation := st.incarnation
	newIncarnation := st.Alive == nil
	if newIncarnation && st.closed {
		// reopen after a closure: next incarnation. A first appearance (closed=false) keeps number 0.
		incarnation++
		st.incarnation = incarnation
	}
	st.closed = false

	v := &Version{
		Incarnation: incarnation,
		Layer:       idx,
		TypeFlag:    typeFlag,
		Size:        hdr.Size,
		Ref:         a.ref,
		metadataKey: metadataKey(hdr),
	}

	if newIncarnation {
		v.PerLayer, v.Cumulative = Added, Added
	} else {
		prev := st.Alive
		// cumulative compares against the first version of THIS incarnation; with no closure since the path
		// first appeared that is simply the earliest version on record
		first := st.Versions[0]
		v.PerLayer = compareVersions(prev, v, e.hasher)
		v.Cumulative = compareVersions(first, v, e.hasher)
		// a directory's entry has no hashed content, so a Modified directory is a metadata-only change unless
		// its type changed (handled above as a type replacement, so here the type already matches)
		if typeFlag == tar.TypeDir && v.PerLayer == Modified {
			v.MetadataOnly = true
		}
	}

	st.Versions = append(st.Versions, v)
	st.Alive = v
	st.Implicit = false
	e.ensureTrie(a.path).state = st

	return Change{
		Path:           a.path,
		Incarnation:    incarnation,
		PerLayer:       v.PerLayer,
		Cumulative:     v.Cumulative,
		NewIncarnation: newIncarnation,
		MetadataOnly:   v.MetadataOnly,
	}, true, nil
}

// EventCount is how many layers added or removed this path: every appearance plus every incarnation closure.
// It matches the Inefficiency.Count semantics of the legacy path-keyed accounting.
func (st *PathState) EventCount() int {
	return len(st.Versions) + st.closures
}

// WastedBytes is every version's size minus the surviving version's size (zero when the path was removed).
func (st *PathState) WastedBytes() int64 {
	var total int64
	for _, v := range st.Versions {
		total += v.Size
	}
	if st.Alive != nil {
		total -= st.Alive.Size
	}
	return total
}

// compareVersions decides Modified vs Unchanged: metadata first, then content hash for regular files. When no
// hasher is available a regular file with matching metadata is treated as Modified: a rewrite really stores new
// bytes, so identical-content rewrites stay visible (and still count as waste), matching the path-keyed legacy
// accounting.
func compareVersions(base, candidate *Version, hasher Hasher) Status {
	if base == nil {
		return Added
	}
	if base.metadataKey != candidate.metadataKey {
		return Modified
	}
	if base.TypeFlag != tar.TypeReg {
		return Unchanged
	}
	if hasher == nil {
		return Modified
	}
	bh, okB := hashVersion(base, hasher)
	ch, okC := hashVersion(candidate, hasher)
	if !okB || !okC || bh != ch {
		return Modified
	}
	return Unchanged
}

// contentDiffer is intentionally not needed: directory entries carry no hashed content, so a Modified directory
// with a matching type is metadata-only by construction (see applyAppearance).

func hashVersion(v *Version, hasher Hasher) (uint64, bool) {
	if v.hasHash {
		return v.hash, true
	}
	h, ok := hasher(v.Ref)
	if ok {
		v.hash, v.hasHash = h, true
	}
	return h, ok
}

// metadataKey is the canonical signature of every header field FileInfo.Compare treats as metadata.
func metadataKey(hdr *tar.Header) string {
	xattrNames := make([]string, 0, len(hdr.PAXRecords))
	xattrs := make(map[string]string)
	for k, v := range hdr.PAXRecords {
		if name, ok := strings.CutPrefix(k, "SCHILY.xattr."); ok {
			xattrNames = append(xattrNames, name)
			xattrs[name] = v
		}
	}
	sort.Strings(xattrNames)
	var xb strings.Builder
	for _, name := range xattrNames {
		fmt.Fprintf(&xb, "%s=%s;", name, xattrs[name])
	}
	return fmt.Sprintf("%d|%o|%d|%d|%s|%s", hdr.Typeflag, hdr.Mode, hdr.Uid, hdr.Gid, hdr.Linkname, xb.String())
}

// stateFor returns the PathState for p, creating it on first sight.
func (e *engine) stateFor(p file.Path) *PathState {
	if st, ok := e.states[p]; ok {
		return st
	}
	st := &PathState{Path: p}
	e.states[p] = st
	e.order = append(e.order, st)
	return st
}

// ensureTrie creates the trie nodes for p and returns its terminal node.
func (e *engine) ensureTrie(p file.Path) *trieNode {
	node := e.root
	for _, seg := range segments(p) {
		next := node.children[seg]
		if next == nil {
			next = &trieNode{children: make(map[string]*trieNode)}
			node.children[seg] = next
		}
		node = next
	}
	return node
}

// findTrie locates the terminal trie node for p, or nil.
func (e *engine) findTrie(p file.Path) *trieNode {
	node := e.root
	for _, seg := range segments(p) {
		next := node.children[seg]
		if next == nil {
			return nil
		}
		node = next
	}
	return node
}

// closePath ends the incarnations of the path and every alive path beneath it, removing them from the alive
// trie. onClose is invoked once per closed state (Removed rows or bookkeeping, depending on the caller).
func (e *engine) closePath(p file.Path, onClose func(*PathState)) {
	node := e.findTrie(p)
	if node == nil {
		return
	}
	var closed []*PathState
	collectClosed(node, &closed)
	detach(e.root, segments(p))
	for _, st := range closed {
		if st.Alive != nil {
			onClose(st)
			st.Alive = nil
		}
		st.Implicit = false
	}
}

// closeChildren ends everything alive directly under dir, keeping dir itself.
func (e *engine) closeChildren(dir file.Path, onClose func(*PathState)) {
	node := e.findTrie(dir)
	if node == nil {
		return
	}
	var closed []*PathState
	for _, child := range node.children {
		collectClosed(child, &closed)
	}
	node.children = make(map[string]*trieNode)
	for _, st := range closed {
		if st.Alive != nil {
			onClose(st)
			st.Alive = nil
		}
		st.Implicit = false
	}
}

// collectClosed gathers every terminal state in a trie subtree.
func collectClosed(n *trieNode, out *[]*PathState) {
	if n.state != nil {
		*out = append(*out, n.state)
	}
	for _, child := range n.children {
		collectClosed(child, out)
	}
}

// detach removes a terminal node and its subtree from the trie by path segments.
func detach(root *trieNode, segs []string) {
	if len(segs) == 0 {
		root.children = make(map[string]*trieNode)
		root.state = nil
		return
	}
	node := root
	for _, seg := range segs[:len(segs)-1] {
		node = node.children[seg]
		if node == nil {
			return
		}
	}
	delete(node.children, segs[len(segs)-1])
}

// segments splits an absolute file path into trie segments.
func segments(p file.Path) []string {
	trimmed := strings.Trim(string(p), "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}
