package iam

import (
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/liamg/iamgo"
)

func parsePolicyFromAttr(attr block.Attribute, owner block.Block, module block.Module) (types.StringValue, error) {

	block, err := module.GetReferencedBlock(attr, owner)
	if err == nil {
		if block.Type() == "data" && block.TypeLabel() == "aws_iam_policy_document" {
			return convertTerraformDocument(block)
		}
	}

	return attr.AsStringValueOrDefault("", owner), nil
}

// https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document
func convertTerraformDocument(block block.Block) (types.StringValue, error) {

	var document iamgo.Document

	if sourceAttr := block.GetAttribute("source_json"); sourceAttr.IsString() {
		doc, err := iamgo.ParseString(sourceAttr.Value().AsString())
		if err != nil {
			return nil, err
		}
		document = *doc
	}

	// TODO overrides
	// TODO add source_policy_documents

	if idAttr := block.GetAttribute("policy_id"); idAttr.IsString() {
		document.Id = idAttr.Value().AsString()
	}

	if versionAttr := block.GetAttribute("version"); versionAttr.IsString() {
		document.Version = iamgo.Version(versionAttr.Value().AsString())
	}

	for _, statementBlock := range block.GetBlocks("statement") {
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
			if !testAttr.IsIterable() {
				continue
			}
			statement.Condition = append(statement.Condition, iamgo.Condition{
				Operator: testAttr.Value().AsString(),
				Key:      variableAttr.Value().AsString(),
				Value:    valuesAttr.ValueAsStrings(),
			})
		}

		document.Statement = append(document.Statement, statement)
	}

	output, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}

	fmt.Printf("\n\n%s\n\n", string(output))

	return types.String(string(output), block.Metadata()), nil
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
