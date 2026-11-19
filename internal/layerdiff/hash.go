package layerdiff

import (
	"io"

	"github.com/cespare/xxhash/v2"
)

// hashReader returns the xxhash of r's contents.
func hashReader(r io.Reader) (uint64, error) {
	h := xxhash.New()
	if _, err := io.Copy(h, r); err != nil {
		return 0, err
	}
	return h.Sum64(), nil
}
