package dive

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"

	"github.com/wagoodman/dive/internal/layerdiff"
)

// Analysis is the result of analyzing an image: the stereoscope image itself plus layer and efficiency stats.
//
// The image is borrowed, not owned: it is the caller's image, and anything that reads file contents through it
// (Image.FileCatalog, Image.OpenReference) only works until the caller runs Image.Cleanup().
type Analysis struct {
	// Ref is a label for the image, as passed to Analyze
	Ref   string
	Image *image.Image
	// Layers is in build order, Layers[i] describes Image.Layers[i]
	Layers []Layer
	// Efficiency is 1.0 for an image without duplicated or removed files, lower otherwise
	Efficiency float64
	// SizeBytes is the sum of all layer sizes
	SizeBytes uint64
	// UserSizeBytes is the sum of all layer sizes except the first (base) layer
	UserSizeBytes uint64
	// WastedBytes is the sum of Inefficiencies sizes
	WastedBytes uint64
	// WastedUserPercent is WastedBytes / UserSizeBytes, 0 when there are no user bytes
	WastedUserPercent float64
	// Inefficiencies is sorted by size, largest first, ties by path
	Inefficiencies []Inefficiency
}

// Layer is the per layer info of an Analysis.
type Layer struct {
	Index int
	// Digest is the layer diff ID
	Digest string
	// Command is the history entry that created the layer, "(missing)" when the image has no history for it
	Command string
	Size    uint64
}

// Inefficiency is a path that wastes bytes because a later layer overwrote or removed it.
type Inefficiency struct {
	Path string
	// Count is how many layers the path shows up in (added or removed)
	Count int
	// SizeBytes is the bytes wasted on the path: every copy layers added minus the copy left in the final image
	SizeBytes uint64
}

// Analyze derives layer info and efficiency stats from an already read stereoscope image. ref only labels the result.
func Analyze(ctx context.Context, ref string, img *image.Image) (*Analysis, error) {
	if img == nil {
		return nil, fmt.Errorf("no image to analyze")
	}

	layers := layerInfo(img)
	efficiency, inefficiencies, err := imageEfficiency(ctx, img)
	if err != nil {
		return nil, err
	}

	var sizeBytes, userSizeBytes, wastedBytes uint64
	for i, l := range layers {
		sizeBytes += l.Size
		if i != 0 {
			userSizeBytes += l.Size
		}
	}
	for _, ineff := range inefficiencies {
		wastedBytes += ineff.SizeBytes
	}

	var wastedUserPercent float64
	if userSizeBytes != 0 {
		wastedUserPercent = float64(wastedBytes) / float64(userSizeBytes)
	}

	return &Analysis{
		Ref:               ref,
		Image:             img,
		Layers:            layers,
		Efficiency:        efficiency,
		SizeBytes:         sizeBytes,
		UserSizeBytes:     userSizeBytes,
		WastedBytes:       wastedBytes,
		WastedUserPercent: wastedUserPercent,
		Inefficiencies:    inefficiencies,
	}, nil
}

// layerInfo pairs layers with history entries. History is in build order and has entries for metadata only
// instructions (empty_layer), which own no layer and are skipped. History is optional, so a layer without an
// entry gets "(missing)".
func layerInfo(img *image.Image) []Layer {
	history := img.Metadata.Config.History
	layers := make([]Layer, len(img.Layers))
	histIdx := 0
	for idx, l := range img.Layers {
		createdBy := "(missing)"
		for histIdx < len(history) && history[histIdx].EmptyLayer {
			histIdx++
		}
		if histIdx < len(history) {
			createdBy = history[histIdx].CreatedBy
			histIdx++
		}
		layers[idx] = Layer{
			Index:   int(l.Metadata.Index),
			Digest:  l.Metadata.Digest,
			Command: strings.TrimPrefix(createdBy, "/bin/sh -c "),
			Size:    uint64(l.Metadata.Size),
		}
	}
	return layers
}

// imageEfficiency scores the image and lists the paths that waste bytes, delegating the per-layer accounting to
// internal/layerdiff. The hasher is nil on purpose: waste bytes never depend on content hashes, and Analyze must
// not read file contents. The layerdiff engine still distinguishes every metadata change; equal-metadata regular
// files read as Unchanged here, which matches the legacy behavior (identical rewrites still waste their bytes).
func imageEfficiency(ctx context.Context, img *image.Image) (float64, []Inefficiency, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	report, err := layerdiff.AnalyzeImage(img, nil)
	if err != nil {
		return 0, nil, err
	}

	var inefficiencies []Inefficiency
	for _, st := range report.Paths {
		waste := st.WastedBytes()
		if waste <= 0 {
			continue
		}
		inefficiencies = append(inefficiencies, Inefficiency{
			Path:      string(st.Path),
			Count:     st.EventCount(),
			SizeBytes: uint64(waste),
		})
	}

	sort.Slice(inefficiencies, func(i, j int) bool {
		a, b := inefficiencies[i], inefficiencies[j]
		if a.SizeBytes != b.SizeBytes {
			return a.SizeBytes > b.SizeBytes
		}
		return a.Path < b.Path
	})

	return report.Totals.Score, inefficiencies, nil
}
