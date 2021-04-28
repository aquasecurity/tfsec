package sarif

type Artifact struct { // https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10541049
	PropertyBag
	Location            *ArtifactLocation `json:"location,omitempty"`
	ParentIndex         *uint             `json:"parentIndex,omitempty"`
	Offset              *uint             `json:"offset,omitempty"`
	Length              int               `json:"length"`
	Roles               []string          `json:"roles,omitempty"`
	MimeType            *string           `json:"mimeType,omitempty"`
	Contents            *ArtifactContent  `json:"contents,omitempty"`
	Encoding            *string           `json:"encoding,omitempty"`
	SourceLanguage      *string           `json:"sourceLanguage,omitempty"`
	Hashes              map[string]string `json:"hashes,omitempty"`
	LastModifiedTimeUtc *string           `json:"lastModifiedTimeUtc,omitempty"`
	Description         *Message          `json:"description,omitempty"`
}

func NewArtifact() *Artifact {
	return &Artifact{}
}

func (a *Artifact) WithLocation(artifactLocation *ArtifactLocation) *Artifact {
	a.Location = artifactLocation
	return a
}

func (a *Artifact) WithParentIndex(parentIndex int) *Artifact {
	i := uint(parentIndex)
	a.ParentIndex = &i
	return a
}

func (a *Artifact) WithOffset(offset int) *Artifact {
	o := uint(offset)
	a.Offset = &o
	return a
}

func (a *Artifact) WithLength(length int) *Artifact {
	a.Length = length
	return a
}

func (a *Artifact) WithRole(role string) *Artifact {
	a.Roles = append(a.Roles, role)
	return a
}

func (a *Artifact) WithMimeType(mimeType string) *Artifact {
	a.MimeType = &mimeType
	return a
}

func (a *Artifact) WithContents(artifactContent *ArtifactContent) *Artifact {
	a.Contents = artifactContent
	return a
}

func (a *Artifact) WithEncoding(encoding string) *Artifact {
	a.Encoding = &encoding
	return a
}

func (a *Artifact) WithSourceLanguage(sourceLanguage string) *Artifact {
	a.SourceLanguage = &sourceLanguage
	return a
}

func (a *Artifact) WithHashes(hashes map[string]string) *Artifact {
	a.Hashes = hashes
	return a
}

func (a *Artifact) WithLastModifiedTimeUtc(lastModified string) *Artifact {
	a.LastModifiedTimeUtc = &lastModified
	return a
}

func (a *Artifact) WithDescription(message *Message) *Artifact {

	return a
}
