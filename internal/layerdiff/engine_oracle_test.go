package layerdiff_test

import (
	"archive/tar"
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wagoodman/dive/internal/imagefixture"
	"github.com/wagoodman/dive/internal/layerdiff"
)

// oracleEntry is one operation in the generated, hand-auditable filesystem. Content sizes are drawn from a tiny
// alphabet so totals stay small and checkable.
type oracleEntry struct {
	path     string
	op       string // add, whiteout, opaque, typeReplace, metadata, hardlink, symlink
	content  string // content id; actual bytes are repeats of it
	typeFlag byte
	link     string
	mode     int64
	layer    int
}

// oracleVersion mirrors one stored copy of a path in a layer, in the naive simulator.
type oracleVersion struct {
	layer       int
	size        int64
	typeFlag    byte
	contentID   string
	incarnation int
}

// oracleFS is the deliberately simple reference model. After every layer it replays the entire overlay
// semantics from scratch over the operation log. It shares no code with the production engine.
type oracleFS struct {
	pathOrder []string
	// versions per path, in appearance order
	versions map[string][]oracleVersion
	// incarnation counter per path
	inc map[string]int
}

func newOracleFS() *oracleFS {
	return &oracleFS{versions: make(map[string][]oracleVersion), inc: make(map[string]int)}
}

func (o *oracleFS) note(p string) {
	if _, ok := o.versions[p]; !ok {
		o.versions[p] = nil
		o.pathOrder = append(o.pathOrder, p)
	}
}

// ensureAncestors registers implicit (zero-byte) directory entries for every ancestor of p that is not yet
// tracked, mirroring stereoscope's auto-created parent paths. An ancestor currently occupied by a non-directory
// (e.g. a symlink from an earlier type replacement) is itself replaced by a directory, which closes its subtree.
func (o *oracleFS) ensureAncestors(alive map[string]oracleVersion, closed map[string]bool, p string, layer int) {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := ""
	for _, seg := range parts[:len(parts)-1] {
		cur += "/" + seg
		o.note(cur)
		existing, ok := alive[cur]
		if !ok {
			v := oracleVersion{layer: layer, size: 0, typeFlag: tar.TypeDir, incarnation: o.inc[cur]}
			o.versions[cur] = append(o.versions[cur], v)
			alive[cur] = v
			continue
		}
		if existing.typeFlag != tar.TypeDir {
			// a non-directory at an ancestor path is replaced by the implicit directory; close everything beneath
			for child := range alive {
				if strings.HasPrefix(child, cur+"/") {
					delete(alive, child)
					closed[child] = true
				}
			}
			o.inc[cur] = existing.incarnation + 1
			v := oracleVersion{layer: layer, size: 0, typeFlag: tar.TypeDir, incarnation: o.inc[cur]}
			o.versions[cur] = append(o.versions[cur], v)
			alive[cur] = v
		}
	}
}

// simulate runs the generated layer operations and returns the expected per-path waste.
func (o *oracleFS) simulate(layers [][]oracleEntry) map[string]int64 {
	// alive maps path -> current entry description in the applied filesystem after each layer
	alive := make(map[string]oracleVersion)
	// closedThis tracks, per layer, paths whose incarnation ended, so the next appearance bumps the number
	for _, ops := range layers {
		closed := make(map[string]bool)
		// first pass: apply closures (whiteout/opaque) to the alive set
		for _, op := range ops {
			switch op.op {
			case "whiteout":
				// op.path is the full target path (the generator stores it directly)
				target := op.path
				for p := range alive {
					if p == target || strings.HasPrefix(p, target+"/") {
						delete(alive, p)
						closed[p] = true
					}
				}
			case "opaque":
				prefix := op.path // directory path, e.g. /d
				// the fixture writes an explicit directory entry alongside the opaque marker, so the model
				// records a zero-byte directory version, matching the engine's key set
				o.note(prefix)
				o.versions[prefix] = append(o.versions[prefix],
					oracleVersion{layer: op.layer, size: 0, typeFlag: tar.TypeDir, incarnation: o.inc[prefix]})
				alive[prefix] = oracleVersion{layer: op.layer, size: 0, typeFlag: tar.TypeDir, incarnation: o.inc[prefix]}
				for p := range alive {
					if strings.HasPrefix(p, prefix+"/") {
						delete(alive, p)
						closed[p] = true
					}
				}
			}
		}
		// second pass: entries in path order
		sorted := append([]oracleEntry(nil), ops...)
		sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].path < sorted[j].path })
		for _, op := range sorted {
			if op.op == "whiteout" || op.op == "opaque" {
				continue
			}
			p := op.path
			o.note(p)
			// stereoscope creates implicit parent directories for any nested path; the model must carry them in
			// alive so a later replacement of a parent can close the subtree
			o.ensureAncestors(alive, closed, p, op.layer)
			inc := o.inc[p]
			if cur, ok := alive[p]; ok {
				if cur.typeFlag != op.typeFlag {
					// type replacement ends the incarnation
					inc = cur.incarnation + 1
					// a directory being replaced hides its subtree
					if cur.typeFlag == tar.TypeDir {
						for child := range alive {
							if strings.HasPrefix(child, p+"/") {
								delete(alive, child)
								closed[child] = true
							}
						}
					}
				}
			} else if closed[p] || len(o.versions[p]) > 0 {
				// first appearance after a closure, or a recreated path: new incarnation
				inc = o.inc[p] + 1
			}
			o.inc[p] = inc
			v := oracleVersion{
				layer:       op.layer,
				size:        int64(len(contentBytes(op.content))),
				typeFlag:    op.typeFlag,
				contentID:   op.content,
				incarnation: inc,
			}
			if op.typeFlag == tar.TypeLink || op.typeFlag == tar.TypeSymlink || op.typeFlag == tar.TypeDir {
				v.size = 0
			}
			o.versions[p] = append(o.versions[p], v)
			alive[p] = v
		}
	}

	waste := make(map[string]int64)
	for _, p := range o.pathOrder {
		// implicit-only directories have no explicit versions and carry no bytes; the engine excludes them too
		if len(o.versions[p]) == 0 {
			continue
		}
		var total int64
		for _, v := range o.versions[p] {
			total += v.size
		}
		if cur, ok := alive[p]; ok {
			total -= cur.size
		}
		waste[p] = total
	}
	return waste
}

// contentBytes maps a one-letter content id to deterministic file bytes.
func contentBytes(id string) string {
	if id == "" {
		return ""
	}
	// ids a..e map to 1..5 repeated characters, keeping sizes tiny
	n := int(id[0]-'a') + 1
	return strings.Repeat(id, n)
}

// generator builds a random sequence of layers over a fixed path universe.
type generator struct {
	rng        *rand.Rand
	paths      []string
	dirs       []string
	layerCount int
}

func newGenerator(seed uint64) *generator {
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	// a handful of directories and leaf paths, nested so subtree cases occur
	dirs := []string{"/d", "/d/sub", "/e"}
	paths := []string{"/d/f1", "/d/f2", "/d/sub/g1", "/d/sub/g2", "/e/h1", "/root.txt"}
	layerCount := 1 + rng.IntN(11) // 1..12
	return &generator{rng: rng, paths: paths, dirs: dirs, layerCount: layerCount}
}

func (g *generator) contentID() string {
	return string(rune('a' + g.rng.IntN(5)))
}

func (g *generator) build() ([][]oracleEntry, [][]imagefixture.Entry) {
	var oracleLayers [][]oracleEntry
	var fixtureLayers [][]imagefixture.Entry
	contentAt := make(map[string]string) // path -> current content id

	for li := 0; li < g.layerCount; li++ {
		var ops []oracleEntry
		var entries []imagefixture.Entry
		// a real tar layer cannot hold two entries at the same path; stereoscope dedupes them, so the generator
		// must not create them either
		usedThisLayer := make(map[string]bool)
		roll := g.rng.Float64()
		switch {
		case roll < 0.55:
			// add or overwrite one or two regular files (distinct paths)
			n := 1 + g.rng.IntN(2)
			for i := 0; i < n; i++ {
				p := g.paths[g.rng.IntN(len(g.paths))]
				if usedThisLayer[p] {
					continue
				}
				usedThisLayer[p] = true
				cid := g.contentID()
				// sometimes rewrite byte-identical content
				if old, ok := contentAt[p]; ok && g.rng.IntN(3) == 0 {
					cid = old
				}
				contentAt[p] = cid
				ops = append(ops, oracleEntry{path: p, op: "add", content: cid, typeFlag: tar.TypeReg, layer: li})
				entries = append(entries, imagefixture.Entry{Name: strings.TrimPrefix(p, "/"), Content: contentBytes(cid)})
			}
		case roll < 0.7:
			// whiteout a file
			p := g.paths[g.rng.IntN(len(g.paths))]
			dir, base := parentAndBase(p)
			// the oracle entry carries the full target path; only the fixture needs the .wh. basename form
			ops = append(ops, oracleEntry{path: p, op: "whiteout", layer: li})
			entries = append(entries, imagefixture.Entry{Name: dir + "/.wh." + base})
			delete(contentAt, p)
		case roll < 0.8:
			// opaque directory
			d := g.dirs[g.rng.IntN(len(g.dirs))]
			ops = append(ops, oracleEntry{path: d, op: "opaque", layer: li})
			entries = append(entries, imagefixture.Entry{Name: strings.TrimPrefix(d, "/") + "/", Type: tar.TypeDir})
			entries = append(entries, imagefixture.Entry{Name: strings.TrimPrefix(d, "/") + "/.wh..wh..opq"})
			for p := range contentAt {
				if strings.HasPrefix(p, d+"/") {
					delete(contentAt, p)
				}
			}
		case roll < 0.88:
			// type replacement: file -> dir with a child, or dir -> symlink
			p := g.paths[g.rng.IntN(len(g.paths))]
			if g.rng.IntN(2) == 0 {
				// file -> dir, plus an explicit child file so the replacement has content
				childID := g.contentID()
				ops = append(ops, oracleEntry{path: p, op: "typeReplace", typeFlag: tar.TypeDir, layer: li})
				ops = append(ops, oracleEntry{path: p + "/child", op: "add", content: childID, typeFlag: tar.TypeReg, layer: li})
				entries = append(entries, imagefixture.Entry{Name: strings.TrimPrefix(p, "/") + "/", Type: tar.TypeDir})
				entries = append(entries, imagefixture.Entry{Name: strings.TrimPrefix(p, "/") + "/child", Content: contentBytes(childID)})
			} else {
				// dir -> symlink
				d := g.dirs[g.rng.IntN(len(g.dirs))]
				ops = append(ops, oracleEntry{path: d, op: "typeReplace", typeFlag: tar.TypeSymlink, link: "/tmp", layer: li})
				entries = append(entries, imagefixture.Entry{Name: strings.TrimPrefix(d, "/"), Type: tar.TypeSymlink, Linkname: "/tmp"})
			}
		case roll < 0.94:
			// metadata-only rewrite of an existing file (same content, executable bit)
			p := g.paths[g.rng.IntN(len(g.paths))]
			cid := contentAt[p]
			if cid == "" {
				cid = g.contentID()
				contentAt[p] = cid
			}
			ops = append(ops, oracleEntry{path: p, op: "metadata", content: cid, typeFlag: tar.TypeReg, mode: 0o755, layer: li})
			entries = append(entries, imagefixture.Entry{Name: strings.TrimPrefix(p, "/"), Mode: 0o755, Content: contentBytes(cid)})
		default:
			// hardlink to another present path (zero bytes)
			target := g.paths[g.rng.IntN(len(g.paths))]
			link := "/hard" + fmt.Sprint(g.rng.IntN(4))
			ops = append(ops, oracleEntry{path: link, op: "hardlink", typeFlag: tar.TypeLink, link: target, layer: li})
			entries = append(entries, imagefixture.Entry{Name: strings.TrimPrefix(link, "/"), Type: tar.TypeLink, Linkname: strings.TrimPrefix(target, "/")})
		}
		oracleLayers = append(oracleLayers, ops)
		fixtureLayers = append(fixtureLayers, entries)
	}
	return oracleLayers, fixtureLayers
}

func parentAndBase(p string) (string, string) {
	idx := strings.LastIndex(p, "/")
	return p[:idx], p[idx+1:]
}

func TestRandomizedOracle(t *testing.T) {
	seeds := 500
	if heavy := os.Getenv("LAYERDIFF_HEAVY_SEEDS"); heavy != "" {
		seeds = 2000
	}
	for seed := uint64(1); seed <= uint64(seeds); seed++ {
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			gen := newGenerator(seed)
			oracleLayers, fixtureLayers := gen.build()

			oracle := newOracleFS()
			wantWaste := oracle.simulate(oracleLayers)

			img := imagefixture.LoadSpec(t, imagefixture.Spec{Format: imagefixture.OCISave, Layers: fixtureLayers})
			report, err := layerdiff.AnalyzeImage(img, layerdiff.ImageHasher(img))
			require.NoError(t, err)

			gotWaste := make(map[string]int64)
			for _, st := range report.Paths {
				// implicit-only dirs have no explicit versions and never carry bytes; the oracle models some of
				// them as zero-byte directory rows, so only compare paths whose waste is nonzero plus the total
				if w := st.WastedBytes(); w > 0 {
					gotWaste[string(st.Path)] = w
				}
			}
			positiveWant := make(map[string]int64)
			for p, w := range wantWaste {
				if w > 0 {
					positiveWant[p] = w
				}
			}
			assert.Equal(t, positiveWant, gotWaste, "seed %d waste mismatch", seed)

			// global invariants
			assert.Equal(t, report.Totals.Wasted, sumMap(wantWaste), "seed %d total mismatch", seed)
			assert.GreaterOrEqual(t, report.Totals.Score, 0.0)
			assert.LessOrEqual(t, report.Totals.Score, 1.0)
			assert.LessOrEqual(t, report.Totals.Wasted, report.Totals.Discovered)

			// layer 0 can never contain a Removed row
			for _, ch := range report.LayerChanges[0] {
				assert.False(t, ch.Removed, "seed %d layer 0 removal", seed)
			}
			// every NewIncarnation appearance is preceded somewhere by a closure
			verifyIncarnationHistory(t, report, seed)
			// hardlink versions always carry zero size
			for _, st := range report.Paths {
				for _, v := range st.Versions {
					if v.TypeFlag == tar.TypeLink {
						assert.Zero(t, v.Size, "seed %d hardlink size", seed)
					}
				}
			}
		})
	}
}

func sumMap(m map[string]int64) int64 {
	var s int64
	for _, v := range m {
		s += v
	}
	return s
}

// verifyIncarnationHistory checks that an incarnation numbered k>0 had at least k closures recorded at the path,
// since every new incarnation follows a closure (including same-layer reopenings that emit no Removed row).
func verifyIncarnationHistory(t *testing.T, report *layerdiff.Report, seed uint64) {
	t.Helper()
	for _, st := range report.Paths {
		maxInc := 0
		for _, v := range st.Versions {
			if v.Incarnation > maxInc {
				maxInc = v.Incarnation
			}
		}
		assert.LessOrEqual(t, maxInc, st.EventCount()-len(st.Versions),
			"seed %d path %s incarnation without closure", seed, st.Path)
	}
}
