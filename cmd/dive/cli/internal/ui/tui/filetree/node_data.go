package filetree

// NodeData is the payload for a FileNode
type NodeData struct {
	ViewInfo ViewInfo
	FileInfo FileInfo
	// DiffType is the status currently shown in the pane: PerLayerDiff in single-layer compare mode,
	// CumulativeDiff in aggregate mode. Keep reading it for rendering and filtering.
	DiffType DiffType
	// PerLayerDiff compares the layer that introduced this node against the filesystem after the previous layer.
	PerLayerDiff DiffType
	// CumulativeDiff compares the node against the first version of its current incarnation (all earlier layers).
	CumulativeDiff DiffType
	// MetadataOnly marks a directory whose own mode/owner/xattr changed while its subtree content did not.
	// It is independent of the aggregated DiffType, which child changes can otherwise overwrite.
	MetadataOnly bool
	// Incarnation bumps every time the path is recreated after a whiteout, opaque directory or type replacement.
	Incarnation int
}

// NewNodeData creates an empty NodeData struct for a FileNode
func NewNodeData() *NodeData {
	return &NodeData{
		ViewInfo: ViewInfo{},
		FileInfo: FileInfo{},
		DiffType: Unmodified,
	}
}

// Copy duplicates a NodeData
func (data *NodeData) Copy() *NodeData {
	return &NodeData{
		ViewInfo:       data.ViewInfo,
		FileInfo:       *data.FileInfo.Copy(),
		DiffType:       data.DiffType,
		PerLayerDiff:   data.PerLayerDiff,
		CumulativeDiff: data.CumulativeDiff,
		MetadataOnly:   data.MetadataOnly,
		Incarnation:    data.Incarnation,
	}
}
