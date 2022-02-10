package iam

import (
	"encoding/json"
	"strings"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/trivy-config-parsers/terraform"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/liamg/iamgo"
)

type wrappedDocument struct {
	source   rules.MetadataProvider
	Document iamgo.Document
}

func parsePolicyFromAttr(attr *terraform.Attribute, owner *terraform.Block, modules terraform.Modules) (types.StringValue, error) {

	documents := findAllPolicies(modules, owner, attr)
	if len(documents) > 0 {
		output, err := json.Marshal(documents[0].Document)
		if err != nil {
			return nil, err
		}
		return types.String(unescapeVars(string(output)), documents[0].source.GetMetadata()), nil
	}

	if attr.IsString() {
		return types.String(unescapeVars(attr.Value().AsString()), owner.GetMetadata()), nil
	}

	return attr.AsStringValueOrDefault("", owner), nil
}

func unescapeVars(input string) string {
	return strings.ReplaceAll(input, "&{", "${")
}

// https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document
func ConvertTerraformDocument(modules terraform.Modules, block *terraform.Block) (*wrappedDocument, error) {

	var document iamgo.Document

	if sourceAttr := block.GetAttribute("source_json"); sourceAttr.IsString() {
		doc, err := iamgo.ParseString(sourceAttr.Value().AsString())
		if err != nil {
			return nil, err
		}
		document = *doc
	}

	if sourceDocumentsAttr := block.GetAttribute("source_policy_documents"); sourceDocumentsAttr.IsIterable() {
		docs := findAllPolicies(modules, block, sourceDocumentsAttr)
		for _, doc := range docs {
			document.Statement = append(document.Statement, doc.Document.Statement...)
		}
	}

	if idAttr := block.GetAttribute("policy_id"); idAttr.IsString() {
		document.Id = idAttr.Value().AsString()
	}

	if versionAttr := block.GetAttribute("version"); versionAttr.IsString() {
		document.Version = iamgo.Version(versionAttr.Value().AsString())
	}

	// count number of statements in the source json to ensure we only override these with regular statements
	sourceCount := len(document.Statement)

	for _, statementBlock := range block.GetBlocks("statement") {

		statement := parseStatement(statementBlock)
		mergeInStatement(&document, statement, sourceCount)
	}

	sourceCount = len(document.Statement)
	if overrideDocumentsAttr := block.GetAttribute("override_policy_documents"); overrideDocumentsAttr.IsIterable() {
		docs := findAllPolicies(modules, block, overrideDocumentsAttr)
		for _, doc := range docs {
			for _, statement := range doc.Document.Statement {
				mergeInStatement(&document, statement, sourceCount)
			}
		}
	}

	return &wrappedDocument{Document: document, source: block}, nil
}

func mergeInStatement(document *iamgo.Document, statement iamgo.Statement, overrideToIndex int) {
	var sidExists bool
	for i, existing := range document.Statement {
		if i >= overrideToIndex {
			break
		}
		if existing.Sid == statement.Sid {
			sidExists = true
			document.Statement[i] = statement
			break
		}
	}
	if !sidExists {
		document.Statement = append(document.Statement, statement)
	}
}

func parseStatement(statementBlock *terraform.Block) iamgo.Statement {
	var statement iamgo.Statement
	if sidAttr := statementBlock.GetAttribute("sid"); sidAttr.IsString() {
		statement.Sid = sidAttr.Value().AsString()
	}
	if actionsAttr := statementBlock.GetAttribute("actions"); actionsAttr.IsIterable() {
		statement.Action = actionsAttr.ValueAsStrings()
	}
	if notActionsAttr := statementBlock.GetAttribute("not_actions"); notActionsAttr.IsIterable() {
		statement.NotAction = notActionsAttr.ValueAsStrings()
	}
	if resourcesAttr := statementBlock.GetAttribute("resources"); resourcesAttr.IsIterable() {
		statement.Resource = resourcesAttr.ValueAsStrings()
	}
	if notResourcesAttr := statementBlock.GetAttribute("not_resources"); notResourcesAttr.IsIterable() {
		statement.NotResource = notResourcesAttr.ValueAsStrings()
	}
	if effectAttr := statementBlock.GetAttribute("effect"); effectAttr.IsString() {
		statement.Effect = iamgo.Effect(effectAttr.Value().AsString())
	} else {
		statement.Effect = iamgo.EffectAllow
	}

	statement.Principal = readPrincipal(statementBlock.GetBlocks("principals"))
	statement.NotPrincipal = readPrincipal(statementBlock.GetBlocks("not_principals"))

	for _, conditionBlock := range statementBlock.GetBlocks("condition") {
		testAttr := conditionBlock.GetAttribute("test")
		if !testAttr.IsString() {
			continue
		}
		variableAttr := conditionBlock.GetAttribute("variable")
		if !variableAttr.IsString() {
			continue
		}
		valuesAttr := conditionBlock.GetAttribute("values")
		if valuesAttr.IsNil() || len(valuesAttr.ValueAsStrings()) == 0 {
			continue
		}
		statement.Condition = append(statement.Condition, iamgo.Condition{
			Operator: testAttr.Value().AsString(),
			Key:      variableAttr.Value().AsString(),
			Value:    valuesAttr.ValueAsStrings(),
		})
	}
	return statement
}

func readPrincipal(blocks terraform.Blocks) *iamgo.Principals {
	var principals *iamgo.Principals
	for _, principalBlock := range blocks {

		typeAttr := principalBlock.GetAttribute("type")
		if !typeAttr.IsString() {
			continue
		}
		identifiersAttr := principalBlock.GetAttribute("identifiers")
		if !identifiersAttr.IsIterable() {
			continue
		}

		if principals == nil {
			principals = &iamgo.Principals{}
		}
		switch typeAttr.Value().AsString() {
		case "*":
			principals.All = true
		case "AWS":
			principals.AWS = append(principals.AWS, identifiersAttr.ValueAsStrings()...)
		case "Federated":
			principals.Federated = append(principals.Federated, identifiersAttr.ValueAsStrings()...)
		case "Service":
			principals.Service = append(principals.Service, identifiersAttr.ValueAsStrings()...)
		case "CanonicalUser":
			principals.CanonicalUsers = append(principals.CanonicalUsers, identifiersAttr.ValueAsStrings()...)
		}
	}
	return principals
}

func findAllPolicies(modules terraform.Modules, parentBlock *terraform.Block, attr *terraform.Attribute) []wrappedDocument {
	var documents []wrappedDocument
	for _, ref := range attr.AllReferences() {
		for _, b := range modules.GetBlocks() {
			if b.Type() != "data" || b.TypeLabel() != "aws_iam_policy_document" {
				continue
			}
			if ref.RefersTo(b.GetMetadata().Reference()) {
				document, err := ConvertTerraformDocument(modules, b)
				if err != nil {
					continue
				}
				documents = append(documents, *document)
				continue
			}
			kref := *ref
			kref.SetKey(parentBlock.GetMetadata().Reference().(*terraform.Reference).RawKey())
			if kref.RefersTo(b.GetMetadata().Reference()) {
				document, err := ConvertTerraformDocument(modules, b)
				if err != nil {
					continue
				}
				documents = append(documents, *document)
			}
		}
	}
	return documents
}
