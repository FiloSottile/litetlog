//go:build mpt

// Package mpt implements the Merkle Patricia Trie, an append-only compressed
// key-value accumulator based on a sparse binary Merkle tree. Keys and values
// are arbitrary 32-byte strings.
//
// It is compatible with the whatsapp_v1 configuration of the akd library, with
// NodeHashingMode::NoLeafEpoch.
//
// This package is NOT STABLE, regardless of the module version, and the API may
// change without notice. To use it, set the mpt build tag.
package mpt

import (
	"errors"
	"slices"
)

type Tree struct {
	Root *Node
	hash func([]byte) [32]byte
}

type Node struct {
	Label Label
	// Left and Right are always non-nil unless the node is a leaf
	// or has label EmptyNodeLabel.
	Left, Right *Node
	// Hash is Hash(value || Hash(Label.Bytes())) where value is
	//   - the entry value for leaf nodes,
	//   - the hash of the children for internal nodes, or
	//   - EmptyValue for empty nodes.
	Hash [32]byte
}

func (t *Tree) nodeHash(label Label, value [32]byte) [32]byte {
	labelHash := t.hash(label.Bytes())
	return t.hash(append(value[:], labelHash[:]...))
}

func (t *Tree) internalNodeValue(left, right *Node) [32]byte {
	return t.hash(append(left.Hash[:], right.Hash[:]...))
}

func NewTree(hash func([]byte) [32]byte) *Tree {
	t := &Tree{hash: hash}
	h := t.nodeHash(RootLabel, t.hash([]byte{0x00}))
	t.Root = &Node{Label: RootLabel, Hash: h, Left: t.newEmptyNode(), Right: t.newEmptyNode()}
	return t
}

func (t *Tree) newEmptyNode() *Node {
	// It's unclear if the nested nodeHash is intentional. If it's not, it might
	// be because the akd_core Configuration method that returns the empty root
	// value is called empty_root_value, while the one that returns the empty
	// sibling value is called empty_node_hash despite both returning values.
	//
	// Anyway, empty_root_value returns H(0x00) while empty_node_hash returns
	// H(EmptyNodeLabel || H(0x00)).
	//
	// This is harmless, so we match it to interoperate with akd.
	h := t.nodeHash(EmptyNodeLabel, t.nodeHash(EmptyNodeLabel, t.hash([]byte{0x00})))
	return &Node{Label: EmptyNodeLabel, Hash: h}
}

func (t *Tree) Leaf(label, value [32]byte) *Node {
	l := Label{256, label}
	return &Node{Label: l, Hash: t.nodeHash(l, value)}
}

// newParentNode creates a new internal (or root) node that replaces the branch
// node with a node that has branch and leaf as children.
func (t *Tree) newParentNode(branch, leaf *Node) (*Node, error) {
	if leaf.Label.BitLen() != 256 {
		return nil, errors.New("leaf is not a leaf node")
	}
	label := LongestCommonPrefix(branch.Label, leaf.Label)
	if label.BitLen() == 256 {
		return nil, errors.New("branch and leaf are equal")
	}
	if label.BitLen() == 0 {
		// The branch is the root node. Either the tree is empty, or we are
		// filling in the empty side of the root node.
		switch {
		case branch.Left.Label != EmptyNodeLabel:
			branch = branch.Left
		case branch.Right.Label != EmptyNodeLabel:
			branch = branch.Right
		default:
			branch = t.newEmptyNode()
		}
	}
	parent := &Node{Label: label}
	switch leaf.Label.SideOf(label) {
	case Left:
		parent.Left = leaf
		parent.Right = branch
	case Right:
		parent.Left = branch
		parent.Right = leaf
	default:
		return nil, errors.New("internal error: leaf is not on either side of prefix")
	}
	parent.Hash = t.nodeHash(label, t.internalNodeValue(parent.Left, parent.Right))
	return parent, nil
}

func (t *Tree) Insert(leaf *Node) error {
	if leaf.Label.BitLen() != 256 {
		return errors.New("leaf is not a leaf node")
	}

	if leaf.Label.SideOf(t.Root.Label) == Left && t.Root.Left.Label == EmptyNodeLabel ||
		leaf.Label.SideOf(t.Root.Label) == Right && t.Root.Right.Label == EmptyNodeLabel {
		// The tree is empty or we are filling in the empty side of the root node.
		newRoot, err := t.newParentNode(t.Root, leaf)
		if err != nil {
			return err
		}
		t.Root = newRoot
		return nil
	}

	// Traverse the tree until we find the first node that is not a prefix of
	// the leaf, which is the point where we will branch the tree and insert the
	// leaf. Keep track of the path we took to get there so we can update the
	// hashes of the nodes we passed through.
	node := t.Root
	var path []*Node
	var parentPointer **Node
	for leaf.Label.HasPrefix(node.Label) {
		if node.Label == leaf.Label {
			return errors.New("leaf already exists in tree")
		}
		switch leaf.Label.SideOf(node.Label) {
		case Left:
			path = append(path, node)
			parentPointer = &node.Left
			node = node.Left
		case Right:
			path = append(path, node)
			parentPointer = &node.Right
			node = node.Right
		}
	}

	node, err := t.newParentNode(node, leaf)
	if err != nil {
		return err
	}
	*parentPointer = node

	slices.Reverse(path)
	for _, node := range path {
		node.Hash = t.nodeHash(node.Label, t.internalNodeValue(node.Left, node.Right))
	}

	return nil
}
