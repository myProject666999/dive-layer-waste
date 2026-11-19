package filetree

import (
	"github.com/anchore/stereoscope/pkg/file"

	"github.com/wagoodman/dive/internal/layerdiff"
)

// toUIDiff maps an engine status to the TUI DiffType vocabulary.
func toUIDiff(s layerdiff.Status) DiffType {
	switch s {
	case layerdiff.Added:
		return Added
	case layerdiff.Modified:
		return Modified
	case layerdiff.Removed:
		return Removed
	default:
		return Unmodified
	}
}

// applyLayerDiff overlays the engine's per-layer and cumulative statuses onto a built UI tree. The engine is the
// source of truth for incarnation boundaries and metadata-only directory changes; the tree's own CompareAndMark
// result keeps driving the colors for implicit directories and child aggregation.
//
// topStart/topStop are the top layer range the key selected: only change rows in that range are applied, so a
// node untouched by the selected layers keeps its tree-derived status. cumulativeDisplay selects which convention
// the visible DiffType (rendering + diff filters) uses: true for the aggregate "compare all layers" view, false
// for the single-layer view.
func (tree *FileTree) applyLayerDiff(report *layerdiff.Report, topStart, topStop int, cumulativeDisplay bool) {
	changes := make(map[file.Path]layerdiff.Change)
	incarnation := make(map[file.Path]int)
	metadataOnly := make(map[file.Path]bool)
	versioned := make(map[file.Path]bool, len(report.Paths))

	for _, st := range report.Paths {
		if len(st.Versions) == 0 {
			// implicit-only directories keep the tree's own aggregated status
			continue
		}
		versioned[st.Path] = true
		if st.Alive != nil {
			incarnation[st.Path] = st.Alive.Incarnation
		}
		for _, v := range st.Versions {
			if v.MetadataOnly {
				metadataOnly[st.Path] = true
			}
		}
	}
	// only the layers this view compares contribute status rows; later layers must not leak into an earlier view
	for layer := topStart; layer <= topStop && layer < len(report.LayerChanges); layer++ {
		for _, ch := range report.LayerChanges[layer] {
			if versioned[ch.Path] {
				changes[ch.Path] = ch
			}
		}
	}

	_ = tree.VisitDepthChildFirst(func(node *FileNode) error {
		p := file.Path(node.Path())
		ch, ok := changes[p]
		if !ok {
			return nil
		}
		node.Data.PerLayerDiff = toUIDiff(ch.PerLayer)
		node.Data.CumulativeDiff = toUIDiff(ch.Cumulative)
		node.Data.Incarnation = incarnation[p]
		node.Data.MetadataOnly = metadataOnly[p]
		// directories keep the tree's own child-aggregated display status; only leaves take the engine's
		// convention directly, so adding a child still shows the parent as Modified rather than Added
		if !node.Data.FileInfo.IsDir {
			if cumulativeDisplay {
				node.Data.DiffType = node.Data.CumulativeDiff
			} else {
				node.Data.DiffType = node.Data.PerLayerDiff
			}
		}
		return nil
	}, nil)
}
