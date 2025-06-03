//go:build mpt

package mpt

func NodeHash(label Label, value [32]byte) [32]byte {
	return nodeHash(label, value)
}

func InternalNodeValue(left, right *Node) [32]byte {
	return internalNodeValue(left, right)
}
