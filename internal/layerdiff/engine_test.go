package layerdiff_test

import (
	"archive/tar"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wagoodman/dive/dive"
	"github.com/wagoodman/dive/internal/imagefixture"
	"github.com/wagoodman/dive/internal/layerdiff"
)

func dirEntry(name string) imagefixture.Entry {
	return imagefixture.Entry{Name: name, Type: tar.TypeDir}
}

func regEntry(name, content string) imagefixture.Entry {
	return imagefixture.Entry{Name: name, Content: content}
}

func whEntry(name string) imagefixture.Entry {
	return imagefixture.Entry{Name: name}
}

// loadSpec runs the engine over an in-memory image, metadata-only comparison.
func loadSpec(t *testing.T, layers [][]imagefixture.Entry) *layerdiff.Report {
	t.Helper()
	img := imagefixture.LoadSpec(t, imagefixture.Spec{Format: imagefixture.OCISave, Layers: layers})
	report, err := layerdiff.AnalyzeImage(img, nil)
	require.NoError(t, err)
	return report
}

// loadSpecHashed runs the engine with a content hasher so equal-content regular files read Unchanged.
func loadSpecHashed(t *testing.T, layers [][]imagefixture.Entry) *layerdiff.Report {
	t.Helper()
	img := imagefixture.LoadSpec(t, imagefixture.Spec{Format: imagefixture.OCISave, Layers: layers})
	report, err := layerdiff.AnalyzeImage(img, layerdiff.ImageHasher(img))
	require.NoError(t, err)
	return report
}

// wasteOf returns the wasted bytes the report attributes to one path.
func wasteOf(t *testing.T, report *layerdiff.Report, want string) int64 {
	t.Helper()
	for _, st := range report.Paths {
		if string(st.Path) == want {
			return st.WastedBytes()
		}
	}
	t.Fatalf("path %s not in report", want)
	return 0
}

func TestAnalyze_HandComputedWaste(t *testing.T) {
	tests := []struct {
		name   string
		layers [][]imagefixture.Entry
		// wantWaste maps path -> hand-computed wasted bytes
		wantWaste map[string]int64
		// wantTotal is the hand-computed image-wide waste
		wantTotal int64
	}{
		{
			// overwrite once: layer1 100 bytes, layer2 200 bytes => the first copy is fully wasted
			name: "overwrite once",
			layers: [][]imagefixture.Entry{
				{regEntry("f", strings.Repeat("a", 100))},
				{regEntry("f", strings.Repeat("b", 200))},
			},
			wantWaste: map[string]int64{"/f": 100},
			wantTotal: 100,
		},
		{
			// overwrite three times: four copies, only the last (40 B) survives
			name: "overwrite three times",
			layers: [][]imagefixture.Entry{
				{regEntry("f", strings.Repeat("a", 10))},
				{regEntry("f", strings.Repeat("b", 20))},
				{regEntry("f", strings.Repeat("c", 30))},
				{regEntry("f", strings.Repeat("d", 40))},
			},
			wantWaste: map[string]int64{"/f": 10 + 20 + 30},
			wantTotal: 60,
		},
		{
			// restore original content with different intermediate size: A(10) -> B(20) -> A(10). All three
			// copies are really stored, only the last 10 survive, so 30 bytes are wasted (this is the nil-hasher
			// path used by the efficiency score; the status-level restore case is TestAnalyze_RestoreContentStatuses)
			name: "restore original content",
			layers: [][]imagefixture.Entry{
				{regEntry("f", strings.Repeat("a", 10))},
				{regEntry("f", strings.Repeat("b", 20))},
				{regEntry("f", strings.Repeat("a", 10))},
			},
			wantWaste: map[string]int64{"/f": 30},
			wantTotal: 30,
		},
		{
			// whole directory replaced by a symlink: every old child's bytes are wasted
			name: "whole directory replaced",
			layers: [][]imagefixture.Entry{
				{
					dirEntry("d/"),
					regEntry("d/a", strings.Repeat("a", 100)),
					regEntry("d/b", strings.Repeat("b", 200)),
				},
				{
					imagefixture.Entry{Name: "d", Type: tar.TypeSymlink, Linkname: "/tmp"},
				},
			},
			wantWaste: map[string]int64{"/d/a": 100, "/d/b": 200},
			wantTotal: 300,
		},
		{
			// metadata-only change on a regular file keeps the same size, but the identical rewrite still stores
			// a second copy, so the old 7 bytes count as waste (same-path duplicates are waste by definition)
			name: "metadata only change",
			layers: [][]imagefixture.Entry{
				{regEntry("run.sh", "script\n")},
				{{Name: "run.sh", Mode: 0o755, Content: "script\n"}},
			},
			wantWaste: map[string]int64{"/run.sh": 7},
			wantTotal: 7,
		},
		{
			// delete then recreate: both versions fully stored, the deleted first copy is wasted
			name: "delete then recreate",
			layers: [][]imagefixture.Entry{
				{regEntry("f", strings.Repeat("a", 100))},
				{whEntry(".wh.f")},
				{regEntry("f", strings.Repeat("c", 50))},
			},
			wantWaste: map[string]int64{"/f": 100},
			wantTotal: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := loadSpec(t, tt.layers)
			assert.Equal(t, tt.wantTotal, report.Totals.Wasted)
			got := make(map[string]int64)
			for _, st := range report.Paths {
				if w := st.WastedBytes(); w > 0 {
					got[string(st.Path)] = w
				}
			}
			assert.Equal(t, tt.wantWaste, got)
			// invariants on every run
			assert.LessOrEqual(t, report.Totals.Wasted, report.Totals.Discovered)
			assert.GreaterOrEqual(t, report.Totals.Score, 0.0)
			assert.LessOrEqual(t, report.Totals.Score, 1.0)
		})
	}
}

func TestAnalyze_RestoreContentStatuses(t *testing.T) {
	// equal sizes so metadata matches and the decision rests on content hashing: A -> B -> A
	report := loadSpecHashed(t, [][]imagefixture.Entry{
		{regEntry("f", strings.Repeat("a", 10))},
		{regEntry("f", strings.Repeat("b", 10))},
		{regEntry("f", strings.Repeat("a", 10))},
	})
	var st *layerdiff.PathState
	for _, candidate := range report.Paths {
		if string(candidate.Path) == "/f" {
			st = candidate
		}
	}
	require.NotNil(t, st)
	require.Len(t, st.Versions, 3)

	// same incarnation throughout (no whiteout)
	for i, v := range st.Versions {
		assert.Equal(t, 0, v.Incarnation, "version %d", i)
	}
	assert.Equal(t, layerdiff.Added, st.Versions[0].PerLayer)
	assert.Equal(t, layerdiff.Added, st.Versions[0].Cumulative)
	assert.Equal(t, layerdiff.Modified, st.Versions[1].PerLayer)
	assert.Equal(t, layerdiff.Modified, st.Versions[1].Cumulative)
	// the worked example from the spec
	assert.Equal(t, layerdiff.Modified, st.Versions[2].PerLayer, "per-layer: A differs from B")
	assert.Equal(t, layerdiff.Unchanged, st.Versions[2].Cumulative, "cumulative: A matches the first version")
}

func TestAnalyze_RecreateIsNewIncarnation(t *testing.T) {
	report := loadSpec(t, [][]imagefixture.Entry{
		{regEntry("f", strings.Repeat("a", 100))},
		{whEntry(".wh.f")},
		{regEntry("f", strings.Repeat("c", 50))},
	})
	var st *layerdiff.PathState
	for _, candidate := range report.Paths {
		if string(candidate.Path) == "/f" {
			st = candidate
		}
	}
	require.NotNil(t, st)
	require.Len(t, st.Versions, 2)
	assert.Equal(t, 0, st.Versions[0].Incarnation)
	assert.Equal(t, 1, st.Versions[1].Incarnation)
	// the recreated path is Added in both conventions, not Modified
	assert.Equal(t, layerdiff.Added, st.Versions[1].PerLayer)
	assert.Equal(t, layerdiff.Added, st.Versions[1].Cumulative)
	// layer 1 carries a Removed row for the old incarnation
	var removed bool
	for _, ch := range report.LayerChanges[1] {
		if string(ch.Path) == "/f" && ch.Removed {
			removed = true
			assert.Equal(t, layerdiff.Removed, ch.PerLayer)
			assert.Equal(t, layerdiff.Removed, ch.Cumulative)
		}
	}
	assert.True(t, removed)
}

func TestAnalyze_FileReplacedByDirectory(t *testing.T) {
	// the confirmed legacy bug: a regular file replaced at the same path by a directory with a child,
	// no whiteout involved
	img := imagefixture.LoadSpec(t, imagefixture.Spec{Format: imagefixture.OCISave, Layers: [][]imagefixture.Entry{
		{regEntry("a", strings.Repeat("a", 123))},
		{
			dirEntry("a/"),
			regEntry("a/b", "new"),
		},
	}})
	report, err := layerdiff.AnalyzeImage(img, nil)
	require.NoError(t, err)

	assert.Equal(t, int64(123), wasteOf(t, report, "/a"), "the old file's bytes are wasted")
	var aState *layerdiff.PathState
	for _, st := range report.Paths {
		if string(st.Path) == "/a" {
			aState = st
		}
	}
	require.NotNil(t, aState)
	require.NotNil(t, aState.Alive)
	assert.Equal(t, byte(tar.TypeDir), aState.Alive.TypeFlag, "the directory incarnation survives")
	// two incarnations at the same path string
	incarnations := map[int]bool{}
	for _, v := range aState.Versions {
		incarnations[v.Incarnation] = true
	}
	assert.Len(t, incarnations, 2)

	// and the dive-level analysis must now count those bytes too
	analysis, err := dive.Analyze(context.Background(), "spec", img)
	require.NoError(t, err)
	assert.Equal(t, uint64(123), analysis.WastedBytes)
}

func TestAnalyze_DirectoryMetadataOnlyFlag(t *testing.T) {
	report := loadSpec(t, [][]imagefixture.Entry{
		{
			dirEntry("d/"),
			regEntry("d/f", "x"),
		},
		{
			{Name: "d/", Type: tar.TypeDir, Mode: 0o700},
			regEntry("d/f", "x"),
		},
	})
	var st *layerdiff.PathState
	for _, candidate := range report.Paths {
		if string(candidate.Path) == "/d" {
			st = candidate
		}
	}
	require.NotNil(t, st)
	require.Len(t, st.Versions, 2)
	assert.True(t, st.Versions[1].MetadataOnly, "directory permission change is metadata-only")
	assert.Equal(t, layerdiff.Modified, st.Versions[1].PerLayer)
}

func TestAnalyze_HardlinkIsZeroBytes(t *testing.T) {
	report := loadSpec(t, [][]imagefixture.Entry{
		{
			regEntry("target", strings.Repeat("t", 500)),
			{Name: "link", Type: tar.TypeLink, Linkname: "target"},
		},
	})
	assert.Equal(t, int64(500), report.Totals.Discovered, "only the target carries bytes; hardlink header size is 0")
	assert.Equal(t, int64(0), report.Totals.Wasted)
}

func TestAnalyze_EventCountMatchesLegacySemantics(t *testing.T) {
	// added once, overwritten once, removed: 3 appearances + 1 closure = 4, as the legacy big.bin case expects
	report := loadSpec(t, [][]imagefixture.Entry{
		{regEntry("f", strings.Repeat("a", 10))},
		{regEntry("f", strings.Repeat("b", 20))},
		{whEntry(".wh.f")},
	})
	var st *layerdiff.PathState
	for _, candidate := range report.Paths {
		if string(candidate.Path) == "/f" {
			st = candidate
		}
	}
	require.NotNil(t, st)
	// two appearances (10 + 20) plus one closure = 3
	assert.Equal(t, 3, st.EventCount())
	assert.Equal(t, int64(30), st.WastedBytes())
}
