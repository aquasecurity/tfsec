package models

type artifact struct { // https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10541049
	Location            *artifactLocation `json:"location,omitempty"`
	ParentIndex         *uint             `json:"parentIndex,omitempty"`
	Offset              *uint             `json:"offset,omitempty"`
	Length              int               `json:"length"`
	Roles               []string          `json:"roles,omitempty"`
	MimeType            *string           `json:"mimeType,omitempty"`
	Contents            *artifactContent  `json:"contents,omitempty"`
	Encoding            *string           `json:"encoding,omitempty"`
	SourceLanguage      *string           `json:"sourceLanguage,omitempty"`
	Hashes              map[string]string `json:"hashes,omitempty"`
	LastModifiedTimeUtc *string           `json:"lastModifiedTimeUtc,omitempty"`
	Description         *Message          `json:"description,omitempty"`
}

type artifactLocation struct { // https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10540865
	URI         *string  `json:"uri,omitempty"`
	URIBaseId   *string  `json:"uriBaseId,omitempty"`
	Index       *uint    `json:"index,omitempty"`
	Description *Message `json:"description,omitempty"`
}

type ArtifactLocationBuilder struct {
	artifactLocation *artifactLocation
}

func (alb *ArtifactLocationBuilder) WithUri(uri string) *ArtifactLocationBuilder {
	alb.artifactLocation.URI = &uri
	return alb
}

func (alb *ArtifactLocationBuilder) WithIndex(index uint) *ArtifactLocationBuilder {
	alb.artifactLocation.Index = &index
	return alb
}

func (alb *ArtifactLocationBuilder) WithUriBaseId(uriBaseId string) *ArtifactLocationBuilder {
	alb.artifactLocation.URIBaseId = &uriBaseId
	return alb
}

func (alb *ArtifactLocationBuilder) WithDescription(messageBuilder MessageBuilder) *ArtifactLocationBuilder {
	alb.artifactLocation.Description = messageBuilder.Get()
	return alb
}

type artifactContent struct { // https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10540860
	Text     *string                   `json:"text,omitempty"`
	Binary   *string                   `json:"binary,omitempty"`
	Rendered *multiformatMessageString `json:"rendered,omitempty"`
}

type ArtifactBuilder struct {
	run      *Run
	artifact *artifact
}

func (run *Run) NewArtifactBuilder() *ArtifactBuilder {
	return &ArtifactBuilder{
		run: run,
		artifact: &artifact{
			Length: -1,
		},
	}
}

func (ab *ArtifactBuilder) Add() *Run {
	ab.run.Artifacts = append(ab.run.Artifacts, ab.artifact)
	return ab.run
}
