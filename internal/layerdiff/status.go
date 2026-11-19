// Package layerdiff computes per-layer and cumulative file statuses across image layers and the bytes wasted
// on overwritten, removed and re-created paths, without copying or merging layer trees.
//
// Two status conventions are kept separate on every result row:
//
//   - PerLayer compares a layer against the filesystem as it looked after the previous layer.
//   - Cumulative compares a layer against the first version of the path's current incarnation (an incarnation
//     starts at the first appearance and again after every whiteout, opaque directory or type replacement).
//
// For example a file with content A in layer 1, B in layer 2 and A again in layer 3 is Modified per-layer in
// layer 3 (A differs from B) but Unchanged cumulative (A matches the incarnation's first version).
package layerdiff

// Status is the change a layer brings to one path.
type Status int

const (
	// Unchanged means the path is present with identical metadata and (for regular files) identical content.
	Unchanged Status = iota
	// Added means the path was not alive after the previous layer and appears in this one.
	Added
	// Modified means the path stays alive but its type, metadata or content changes.
	Modified
	// Removed means a whiteout, an opaque directory or a type replacement ends the path in this layer.
	Removed
)

// String is the stable wire spelling used by the JSON export; do not reorder the constants above.
func (s Status) String() string {
	switch s {
	case Unchanged:
		return "Unchanged"
	case Added:
		return "Added"
	case Modified:
		return "Modified"
	case Removed:
		return "Removed"
	default:
		return "Unknown"
	}
}

// MarshalText renders Status as its stable string name in JSON output.
func (s Status) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}
