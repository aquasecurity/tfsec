package iam

import (
	"encoding/json"

	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/liamg/iamgo"
)

func parsePolicyFromAttr(attr block.Attribute, owner block.Block, module block.Module) (types.StringValue, error) {

	documents := findAllPolicies(module, owner, attr)
	if len(documents) > 0 {
		output, err := json.Marshal(documents[0])
		if err != nil {
			return nil, err
		}
		return types.String(string(output), owner.Metadata()), nil
	}

	return attr.AsStringValueOrDefault("", owner), nil
}

// https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document
func convertTerraformDocument(module block.Module, block block.Block) (*iamgo.Document, error) {

	var document iamgo.Document

	if sourceAttr := block.GetAttribute("source_json"); sourceAttr.IsString() {
		doc, err := iamgo.ParseString(sourceAttr.Value().AsString())
		if err != nil {
			return nil, err
		}
		document = *doc
	}

	if sourceDocumentsAttr := block.GetAttribute("source_policy_documents"); sourceDocumentsAttr.IsIterable() {
		docs := findAllPolicies(module, block, sourceDocumentsAttr)
		for _, doc := range docs {
			document.Statement = append(document.Statement, doc.Statement...)
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

		var sidExists bool
		for i, existing := range document.Statement {
			if i >= sourceCount {
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

	if overrideDocumentsAttr := block.GetAttribute("override_policy_documents"); overrideDocumentsAttr.IsIterable() {
		docs := findAllPolicies(module, block, overrideDocumentsAttr)
		for _, doc := range docs {
			for _, statement := range doc.Statement {
				var sidExists bool
				for i, existing := range document.Statement {
					if i >= sourceCount {
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
		}
	}

	return &document, nil
}

func parseStatement(statementBlock block.Block) iamgo.Statement {
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
		if testAttr.IsNil() {
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

func readPrincipal(blocks block.Blocks) *iamgo.Principals {
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

func findAllPolicies(module block.Module, parentBlock block.Block, attr block.Attribute) []*iamgo.Document {
	var documents []*iamgo.Document
	for _, ref := range attr.AllReferences() {
		for _, block := range module.GetBlocks() {
			if block.Type() != "data" || block.TypeLabel() != "aws_iam_policy_document" {
				continue
			}
			if ref.RefersTo(block.Reference()) {
				document, err := convertTerraformDocument(module, block)
				if err != nil {
					continue
				}
				documents = append(documents, document)
				continue
			}
			kref := *ref
			kref.SetKey(parentBlock.Reference().RawKey())
			if kref.RefersTo(block.Reference()) {
				document, err := convertTerraformDocument(module, block)
				if err != nil {
					continue
				}
				documents = append(documents, document)
			}
		}
	}
	return documents
}
