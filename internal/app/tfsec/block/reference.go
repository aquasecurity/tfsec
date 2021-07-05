package block

import (
	"strings"
)

type Reference struct {
	blockType  Type
	typeLabel  string
	nameLabel  string
	fullString string
}

func newReference(parts []string) *Reference {

	var ref Reference

	if len(parts) > 0 {

		blockType, err := TypeFromRefName(parts[0])
		if err != nil {
			blockType = &TypeResource
		}

		ref.blockType = *blockType

		if ref.blockType.removeTypeInReference {
			ref.typeLabel = parts[0]
			if len(parts) > 1 {
				ref.nameLabel = parts[1]
			}
		} else {
			if len(parts) > 1 {
				ref.typeLabel = parts[1]
				if len(parts) > 2 {
					ref.nameLabel = parts[2]
				}
			}
		}
	}

	ref.fullString = strings.Join(parts, ".")

	return &ref
}

func (r *Reference) BlockType() Type {
	return r.blockType
}

func (r *Reference) TypeLabel() string {
	return r.typeLabel
}

func (r *Reference) NameLabel() string {
	return r.nameLabel
}

func (r *Reference) String() string {
	return r.fullString
}

func (r *Reference) RefersTo(b Block) bool {
	if r.BlockType() != b.Reference().BlockType() {
		return false
	}
	if r.TypeLabel() != b.Reference().TypeLabel() {
		return false
	}
	if r.NameLabel() != b.Reference().NameLabel() {
		return false
	}
	return true
}
