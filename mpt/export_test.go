//go:build mpt

package mpt

func (t *Tree) Hash(b []byte) [32]byte {
	return t.hash(b)
}

func (t *Tree) NodeHash(label Label, value [32]byte) [32]byte {
	return t.nodeHash(label, value)
}

func (t *Tree) InternalNodeValue(left, right *Node) [32]byte {
	return t.internalNodeValue(left, right)
}
