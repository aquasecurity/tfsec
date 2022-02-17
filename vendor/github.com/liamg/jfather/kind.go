package jfather

type Kind uint8

const (
	KindUnknown Kind = iota
	KindNull
	KindNumber
	KindString
	KindBoolean
	KindArray
	KindObject
)
