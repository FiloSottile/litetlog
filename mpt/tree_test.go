//go:build mpt

package mpt_test

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"testing"

	"lukechampine.com/blake3"

	. "filippo.io/torchwood/mpt"
)

func TestFullTree(t *testing.T) {
	tree := NewTree(blake3.Sum256)
	for n := range 1000 {
		if err := Validate(tree); err != nil {
			t.Fatalf("tree is invalid before inserting %d: %v", n, err)
		}

		var label [32]byte
		binary.LittleEndian.PutUint16(label[:], uint16(n))
		value := tree.Hash(label[:])
		leaf := tree.Leaf(label, value)

		if err := tree.Insert(leaf); err != nil {
			t.Fatalf("failed to insert leaf %d: %v", n, err)
		}
	}
	if err := Validate(tree); err != nil {
		t.Fatalf("tree is invalid after inserting 1000 leaves: %v", err)
	}
	rootHash := tree.Root.Hash

	tree = NewTree(blake3.Sum256)
	for n := 999; n >= 0; n-- {
		var label [32]byte
		binary.LittleEndian.PutUint16(label[:], uint16(n))
		value := tree.Hash(label[:])
		leaf := tree.Leaf(label, value)

		if err := tree.Insert(leaf); err != nil {
			t.Fatalf("failed to insert leaf %d: %v", n, err)
		}
	}
	if tree.Root.Hash != rootHash {
		t.Fatalf("after inserting in reverse order: got %x, want %x", tree.Root.Hash, rootHash)
	}

	tree = NewTree(blake3.Sum256)
	for _, n := range rand.Perm(1000) {
		var label [32]byte
		binary.LittleEndian.PutUint16(label[:], uint16(n))
		value := tree.Hash(label[:])
		leaf := tree.Leaf(label, value)

		if err := tree.Insert(leaf); err != nil {
			t.Fatalf("failed to insert leaf %d: %v", n, err)
		}
	}
	if tree.Root.Hash != rootHash {
		t.Fatalf("after inserting in random order: got %x, want %x", tree.Root.Hash, rootHash)
	}
}

func TestAccumulated(t *testing.T) {
	source := blake3.New(0, nil).XOF()
	sink := blake3.New(32, nil)

	for range 100 {
		tree := NewTree(blake3.Sum256)
		sink.Write(tree.Root.Hash[:])
		for range 1000 {
			var label, value [32]byte
			source.Read(label[:])
			source.Read(value[:])
			leaf := tree.Leaf(label, value)

			if err := tree.Insert(leaf); err != nil {
				t.Fatalf("failed to insert leaf: %v", err)
			}
			sink.Write(tree.Root.Hash[:])
		}
	}

	exp := "dfa5cc5758518f612c53d3434688996895373f29e2df61b7f7c26f0e25b095eb"
	result := sink.Sum(nil)
	if hex.EncodeToString(result) != exp {
		t.Fatalf("expected hash %s, got %x", exp, result)
	}
}

func Validate(tree *Tree) error {
	root := tree.Root
	if root.Label != RootLabel {
		return errors.New("root node has invalid label")
	}
	if root.Left.Label == EmptyNodeLabel && root.Right.Label == EmptyNodeLabel {
		if root.Hash != tree.NodeHash(RootLabel, tree.Hash([]byte{0x00})) {
			return errors.New("root node hash does not match empty value")
		}
		return nil
	}
	return validateNode(tree, root)
}

func validateNode(tree *Tree, node *Node) error {
	labelBytes := node.Label.Bytes()
	label, err := NewLabel(node.Label.BitLen(), ([32]byte)(labelBytes[4:]))
	if err != nil {
		return err
	}
	if node.Label != label {
		return errors.New("node label is not valid")
	}

	if node.Label.BitLen() == 256 {
		if node.Left != nil || node.Right != nil {
			return errors.New("leaf node has children")
		}
		return nil
	}

	if node.Left.Label != EmptyNodeLabel {
		if node.Left.Label.SideOf(node.Label) != Left {
			return errors.New("left child is not on the left side of the label")
		}
		if err := validateNode(tree, node.Left); err != nil {
			return err
		}
	} else {
		if node.Label != RootLabel {
			return errors.New("left child is empty but node is not root")
		}
	}
	if node.Right.Label != EmptyNodeLabel {
		if node.Right.Label.SideOf(node.Label) != Right {
			return errors.New("right child is not on the right side of the label")
		}
		if err := validateNode(tree, node.Right); err != nil {
			return err
		}
	} else {
		if node.Label != RootLabel {
			return errors.New("right child is empty but node is not root")
		}
	}

	if node.Hash != tree.NodeHash(node.Label, tree.InternalNodeValue(node.Left, node.Right)) {
		return errors.New("node hash does not match children")
	}

	return nil
}
