package iamgo

type Document struct {
	Version   Version    `json:"Version"`
	Id        string     `json:"Id,omitempty"`
	Statement Statements `json:"Statement"`
}
