package export

import (
	"github.com/wagoodman/dive/internal/layerdiff"
)

// LayerDiff is the additive, machine-readable per-layer and cumulative diff block. It never reuses or renames
// the existing image/layer keys; older consumers can ignore it entirely.
type LayerDiff struct {
	Paths  []DiffPath  `json:"paths"`
	Layers []DiffLayer `json:"layers"`
}

// DiffPath is one path string with every version (appearance) it had across layers.
type DiffPath struct {
	Path         string        `json:"path"`
	Incarnations int           `json:"incarnations"`
	WastedBytes  int64         `json:"wastedBytes"`
	Versions     []DiffVersion `json:"versions"`
}

// DiffVersion is one catalog-backed appearance of a path in one layer.
type DiffVersion struct {
	Layer            int    `json:"layer"`
	Incarnation      int    `json:"incarnation"`
	TypeFlag         byte   `json:"typeFlag"`
	Size             int64  `json:"size"`
	PerLayerStatus   string `json:"perLayerStatus"`
	CumulativeStatus string `json:"cumulativeStatus"`
	MetadataOnly     bool   `json:"metadataOnly"`
}

// DiffLayer groups the changes one layer introduced.
type DiffLayer struct {
	Index   int          `json:"index"`
	Changes []DiffChange `json:"changes"`
}

// DiffChange is one appearance or removal row for a layer.
type DiffChange struct {
	Path             string `json:"path"`
	Incarnation      int    `json:"incarnation"`
	PerLayerStatus   string `json:"perLayerStatus"`
	CumulativeStatus string `json:"cumulativeStatus"`
	NewIncarnation   bool   `json:"newIncarnation"`
	MetadataOnly     bool   `json:"metadataOnly"`
	Removed          bool   `json:"removed"`
}

// newLayerDiff builds the additive block from the engine report. The hasher distinguishes equal-metadata
// regular files; pass nil to keep the comparison metadata-only.
func newLayerDiff(report *layerdiff.Report) LayerDiff {
	diff := LayerDiff{
		Paths:  make([]DiffPath, 0, len(report.Paths)),
		Layers: make([]DiffLayer, report.LayerCount),
	}

	incarnationCount := func(st *layerdiff.PathState) int {
		seen := make(map[int]struct{})
		for _, v := range st.Versions {
			seen[v.Incarnation] = struct{}{}
		}
		return len(seen)
	}

	for _, st := range report.Paths {
		// implicit-only directories have no explicit versions and no machine-readable row
		if len(st.Versions) == 0 {
			continue
		}
		dp := DiffPath{
			Path:         string(st.Path),
			Incarnations: incarnationCount(st),
			WastedBytes:  st.WastedBytes(),
			Versions:     make([]DiffVersion, 0, len(st.Versions)),
		}
		for _, v := range st.Versions {
			dp.Versions = append(dp.Versions, DiffVersion{
				Layer:            v.Layer,
				Incarnation:      v.Incarnation,
				TypeFlag:         v.TypeFlag,
				Size:             v.Size,
				PerLayerStatus:   v.PerLayer.String(),
				CumulativeStatus: v.Cumulative.String(),
				MetadataOnly:     v.MetadataOnly,
			})
		}
		diff.Paths = append(diff.Paths, dp)
	}

	for i := range report.LayerChanges {
		dl := DiffLayer{Index: i, Changes: make([]DiffChange, 0, len(report.LayerChanges[i]))}
		for _, ch := range report.LayerChanges[i] {
			dl.Changes = append(dl.Changes, DiffChange{
				Path:             string(ch.Path),
				Incarnation:      ch.Incarnation,
				PerLayerStatus:   ch.PerLayer.String(),
				CumulativeStatus: ch.Cumulative.String(),
				NewIncarnation:   ch.NewIncarnation,
				MetadataOnly:     ch.MetadataOnly,
				Removed:          ch.Removed,
			})
		}
		diff.Layers[i] = dl
	}

	return diff
}
