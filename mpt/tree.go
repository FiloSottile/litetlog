// Package mpt implements the Merkle Patricia Trie, an append-only compressed
// key-value accumulator based on a sparse binary Merkle tree. Keys and values
// are arbitrary 32-byte strings.
//
// It is compatible with the whatsapp_v1 configuration of the akd library, with
// NodeHashingMode::NoLeafEpoch.
//
// This package is NOT STABLE, regardless of the module version, and the API may
// change without notice.
package mpt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

type HashFunc func([]byte) [32]byte

type Node struct {
	Label Label
	// If the node is the root, Left and/or Right may be EmptyNodeLabel.
	// If the node is a leaf or empty, Left and Right are undefined.
	Left, Right Label
	// Hash is Hash(value || Hash(Label.Bytes())) where value is
	//   - the entry value for leaf nodes,
	//   - the hash of the children for internal nodes, or
	//   - EmptyValue for empty nodes.
	Hash [32]byte
}

func (n *Node) String() string {
	var s strings.Builder
	fmt.Fprintf(&s, "Node{%s", n.Label)
	if !n.Label.IsLeaf() && n.Label != EmptyNodeLabel {
		fmt.Fprintf(&s, " l:%s r:%s", n.Left, n.Right)
	}
	fmt.Fprintf(&s, " h:%x}", n.Hash)
	return s.String()
}

func nodeHash(h HashFunc, label Label, value [32]byte) [32]byte {
	l := make([]byte, 0, 4+32)
	l = binary.BigEndian.AppendUint32(l, label.bitLen)
	l = append(l, label.bytes[:]...)
	labelHash := h(l)
	return h(append(value[:], labelHash[:]...))
}

func internalNodeValue(h HashFunc, left, right *Node) [32]byte {
	return h(append(left.Hash[:], right.Hash[:]...))
}

func newRootNode(h HashFunc) *Node {
	return &Node{
		Label: RootLabel,
		Hash:  nodeHash(h, RootLabel, h([]byte{0x00})),
		Left:  EmptyNodeLabel,
		Right: EmptyNodeLabel,
	}
}

func newEmptyNode(h HashFunc) *Node {
	// It's unclear if the nested nodeHash is intentional. If it's not, it might
	// be because the akd_core Configuration method that returns the empty root
	// value is called empty_root_value, while the one that returns the empty
	// sibling value is called empty_node_hash despite both returning values.
	//
	// Anyway, empty_root_value returns H(0x00) while empty_node_hash returns
	// H(EmptyNodeLabel || H(0x00)).
	//
	// This is harmless, so we match it to interoperate with akd.
	hash := nodeHash(h, EmptyNodeLabel, nodeHash(h, EmptyNodeLabel, h([]byte{0x00})))
	return &Node{Label: EmptyNodeLabel, Hash: hash}
}

func newLeaf(h HashFunc, label, value [32]byte) *Node {
	l := Label{256, label}
	return &Node{Label: l, Hash: nodeHash(h, l, value)}
}

// newParentNode returns a new internal (or root) node with the provided
// children, of which at most one may be an empty node.
func newParentNode(h HashFunc, a, b *Node) (*Node, error) {
	label := LongestCommonPrefix(b.Label, a.Label)
	if label.BitLen() == 256 {
		return nil, errors.New("nodes are equal")
	}
	if a.Label == EmptyNodeLabel {
		a, b = b, a
	}
	if a.Label == EmptyNodeLabel {
		return nil, errors.New("both nodes are empty")
	}
	parent := &Node{Label: label}
	switch a.Label.SideOf(label) {
	case Left:
		parent.Left = a.Label
		parent.Right = b.Label
		parent.Hash = nodeHash(h, label, internalNodeValue(h, a, b))
	case Right:
		parent.Left = b.Label
		parent.Right = a.Label
		parent.Hash = nodeHash(h, label, internalNodeValue(h, b, a))
	default:
		return nil, errors.New("internal error: non-empty node is not on either side of prefix")
	}
	return parent, nil
}

type Tree struct {
	s Storage
	h HashFunc
}

func NewTree(h HashFunc, s Storage) *Tree {
	return &Tree{h: h, s: s}
}

func InitStorage(h HashFunc, s Storage) error {
	return s.Store(newEmptyNode(h), newRootNode(h))
}

func (t *Tree) Insert(label, value [32]byte) error {
	leaf := newLeaf(t.h, label, value)

	path, err := t.s.LoadPath(leaf.Label)
	if err != nil {
		return err
	}

	node := leaf
	var changed []*Node
	changed = append(changed, node)
	for _, sibling := range path {
		node, err = newParentNode(t.h, sibling, node)
		if err != nil {
			return err
		}
		changed = append(changed, node)
	}

	return t.s.Store(changed...)
}
