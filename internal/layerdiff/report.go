package layerdiff

import (
	"archive/tar"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"

	"github.com/wagoodman/dive/internal/layertree"
)

// imageResolver adapts layertree.Header to the EntryResolver interface.
type imageResolver struct {
	img *image.Image
}

func (r imageResolver) Header(ref *file.Reference) (*tar.Header, bool) {
	return layertree.Header(r.img, ref)
}

// FromImage builds the layer inputs a stereoscope image already indexed.
func FromImage(img *image.Image) []LayerInput {
	layers := make([]LayerInput, len(img.Layers))
	for i, l := range img.Layers {
		layers[i] = LayerInput{Tree: l.Tree}
	}
	return layers
}

// AnalyzeImage runs the engine against a fully read stereoscope image. A nil hasher compares metadata only;
// pass a content hasher when per-layer/cumulative statuses must distinguish equal-metadata regular files.
func AnalyzeImage(img *image.Image, hasher Hasher) (*Report, error) {
	return Analyze(FromImage(img), imageResolver{img: img}, hasher)
}

// ImageHasher reads and xxhashes regular file contents through the image catalog, caching per file reference so
// each reference is opened at most once.
func ImageHasher(img *image.Image) Hasher {
	cache := make(map[file.ID]uint64)
	return func(ref *file.Reference) (uint64, bool) {
		if ref == nil {
			return 0, false
		}
		if h, ok := cache[ref.ID()]; ok {
			return h, true
		}
		rc, err := img.OpenReference(*ref)
		if err != nil {
			return 0, false
		}
		defer rc.Close()
		h, err := hashReader(rc)
		if err != nil {
			return 0, false
		}
		cache[ref.ID()] = h
		return h, true
	}
}
