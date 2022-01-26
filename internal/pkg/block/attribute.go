package block

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/debug"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

type Attribute struct {
	hclAttribute *hcl.Attribute
	module       string
	ctx          *Context
	metadata     types.Metadata
}

func NewAttribute(attr *hcl.Attribute, ctx *Context, module string, parent types.Metadata, parentRef *Reference) *Attribute {
	rng := types.NewRange(
		attr.Range.Filename,
		attr.Range.Start.Line,
		attr.Range.End.Line,
	)
	metadata := types.NewMetadata(rng, extendReference(parentRef, attr.Name))
	return &Attribute{
		hclAttribute: attr,
		ctx:          ctx,
		module:       module,
		metadata:     metadata.WithParent(parent),
	}
}

func (a *Attribute) Metadata() types.Metadata {
	return a.metadata
}

func (a *Attribute) GetMetadata() *types.Metadata {
	// this is hacky but we need to satisfy the upstream metadata provider interface...
	return &a.metadata
}

func (a *Attribute) GetRawValue() interface{} {
	switch typ := a.Type(); typ {
	case cty.String:
		return a.Value().AsString()
	case cty.Bool:
		return a.Value().True()
	case cty.Number:
		float, _ := a.Value().AsBigFloat().Float64()
		return float
	default:
		switch {
		case typ.IsTupleType(), typ.IsListType():
			values := a.Value().AsValueSlice()
			if len(values) == 0 {
				return []string{}
			}
			switch values[0].Type() {
			case cty.String:
				var output []string
				for _, value := range values {
					output = append(output, value.AsString())
				}
				return output
			case cty.Number:
				var output []float64
				for _, value := range values {
					bf := value.AsBigFloat()
					f, _ := bf.Float64()
					output = append(output, f)
				}
				return output
			case cty.Bool:
				var output []bool
				for _, value := range values {
					output = append(output, value.True())
				}
				return output
			}
		}
	}
	return nil
}

func (attr *Attribute) AsBytesValueOrDefault(defaultValue []byte, parent *Block) types.BytesValue {
	if attr.IsNil() {
		return types.BytesDefault(defaultValue, parent.Metadata())
	}
	if attr.IsNotResolvable() || !attr.IsString() {
		return types.BytesUnresolvable(attr.Metadata())
	}
	return types.BytesExplicit(
		[]byte(attr.Value().AsString()),
		*(attr.GetMetadata()),
	)
}

func (attr *Attribute) AsStringValueOrDefault(defaultValue string, parent *Block) types.StringValue {
	if attr.IsNil() {
		return types.StringDefault(defaultValue, parent.Metadata())
	}
	if attr.IsNotResolvable() || !attr.IsString() {
		return types.StringUnresolvable(attr.Metadata())
	}
	return types.StringExplicit(
		attr.Value().AsString(),
		*(attr.GetMetadata()),
	)
}

func (attr *Attribute) AsBoolValueOrDefault(defaultValue bool, parent *Block) types.BoolValue {
	if attr.IsNil() {
		return types.BoolDefault(defaultValue, parent.Metadata())
	}
	if attr.IsNotResolvable() || !attr.IsBool() {
		return types.BoolUnresolvable(attr.Metadata())
	}
	return types.BoolExplicit(
		attr.IsTrue(),
		*(attr.GetMetadata()),
	)
}

func (attr *Attribute) AsIntValueOrDefault(defaultValue int, parent *Block) types.IntValue {
	if attr.IsNil() {
		return types.IntDefault(defaultValue, parent.Metadata())
	}
	if attr.IsNotResolvable() || !attr.IsNumber() {
		return types.IntUnresolvable(attr.Metadata())
	}
	big := attr.Value().AsBigFloat()
	flt, _ := big.Float64()
	return types.IntExplicit(
		int(flt),
		*(attr.GetMetadata()),
	)
}

func (attr *Attribute) IsLiteral() bool {
	if attr == nil {
		return false
	}
	return len(attr.hclAttribute.Expr.Variables()) == 0
}

func (attr *Attribute) IsResolvable() bool {
	if attr == nil {
		return false
	}
	return attr.Value() != cty.NilVal && attr.Value().IsKnown()
}

func (attr *Attribute) IsNotResolvable() bool {
	return !attr.IsResolvable()
}

func (attr *Attribute) Type() cty.Type {
	if attr == nil {
		return cty.NilType
	}
	return attr.Value().Type()
}

func (attr *Attribute) IsIterable() bool {
	if attr == nil {
		return false
	}
	return attr.Value().Type().IsListType() || attr.Value().Type().IsCollectionType() || attr.Value().Type().IsObjectType() || attr.Value().Type().IsMapType() || attr.Value().Type().IsListType() || attr.Value().Type().IsSetType() || attr.Value().Type().IsTupleType()
}

func (attr *Attribute) Each(f func(key cty.Value, val cty.Value)) {
	if attr == nil {
		return
	}
	val := attr.Value()
	val.ForEachElement(func(key cty.Value, val cty.Value) (stop bool) {
		f(key, val)
		return false
	})
}

func (attr *Attribute) IsString() bool {
	if attr == nil {
		return false
	}
	return !attr.Value().IsNull() && attr.Value().IsKnown() && attr.Value().Type() == cty.String
}

func (attr *Attribute) IsNumber() bool {
	if attr == nil {
		return false
	}
	return !attr.Value().IsNull() && attr.Value().IsKnown() && attr.Value().Type() == cty.Number
}

func (attr *Attribute) IsBool() bool {
	if attr == nil {
		return false
	}
	switch attr.Value().Type() {
	case cty.Bool, cty.Number:
		return true
	case cty.String:
		val := attr.Value().AsString()
		val = strings.Trim(val, "\"")
		return strings.EqualFold(val, "false") || strings.EqualFold(val, "true")
	}
	return false
}

func (attr *Attribute) Value() (ctyVal cty.Value) {
	if attr == nil {
		return cty.NilVal
	}
	defer func() {
		if err := recover(); err != nil {
			ctyVal = cty.NilVal
		}
	}()
	ctyVal, _ = attr.hclAttribute.Expr.Value(attr.ctx.Inner())
	if !ctyVal.IsKnown() {
		return cty.NilVal
	}
	return ctyVal
}

func (attr *Attribute) Name() string {
	if attr == nil {
		return ""
	}
	return attr.hclAttribute.Name
}

func (attr *Attribute) ValueAsStrings() []string {
	if attr == nil {
		return nil
	}
	return getStrings(attr.hclAttribute.Expr, attr.ctx.Inner())
}

func getStrings(expr hcl.Expression, ctx *hcl.EvalContext) []string {
	var results []string
	switch t := expr.(type) {
	case *hclsyntax.TupleConsExpr:
		for _, expr := range t.Exprs {
			results = append(results, getStrings(expr, ctx)...)
		}
	case *hclsyntax.FunctionCallExpr, *hclsyntax.ConditionalExpr:
		subVal, err := t.Value(ctx)
		if err == nil && subVal.Type() == cty.String {
			results = append(results, subVal.AsString())
		}
	case *hclsyntax.LiteralValueExpr:
		if t.Val.Type() == cty.String {
			results = append(results, t.Val.AsString())
		}
	case *hclsyntax.TemplateExpr:
		// walk the parts of the expression to ensure that it has a literal value
		for _, p := range t.Parts {
			results = append(results, getStrings(p, ctx)...)
		}
	case *hclsyntax.ScopeTraversalExpr:
		// handle the case for referencing a data
		if len(t.Variables()) > 0 {
			if t.Variables()[0].RootName() == "data" {
				results = append(results, "Data Reference")
				return results
			}
		}
		subVal, err := t.Value(ctx)
		if err == nil && subVal.Type() == cty.String {
			results = append(results, subVal.AsString())
		}
	}
	return results
}

func (attr *Attribute) listContains(val cty.Value, stringToLookFor string, ignoreCase bool) bool {
	if attr == nil {
		return false
	}
	valueSlice := val.AsValueSlice()
	for _, value := range valueSlice {
		stringToTest := value
		if value.Type().IsObjectType() || value.Type().IsMapType() {
			valueMap := value.AsValueMap()
			stringToTest = valueMap["key"]
		}
		if value.Type().HasDynamicTypes() {
			// References without a value can't logically "contain" a some string to check against.
			return false
		}
		if !value.IsKnown() {
			continue
		}
		if ignoreCase && strings.EqualFold(stringToTest.AsString(), stringToLookFor) {
			return true
		}
		if stringToTest.AsString() == stringToLookFor {
			return true
		}
	}
	return false
}

func (attr *Attribute) mapContains(checkValue interface{}, val cty.Value) bool {
	if attr == nil {
		return false
	}
	valueMap := val.AsValueMap()
	switch t := checkValue.(type) {
	case map[interface{}]interface{}:
		for k, v := range t {
			for key, value := range valueMap {
				rawValue := getRawValue(value)
				if key == k && evaluate(v, rawValue) {
					return true
				}
			}
		}
		return false
	case map[string]interface{}:
		for k, v := range t {
			for key, value := range valueMap {
				rawValue := getRawValue(value)
				if key == k && evaluate(v, rawValue) {
					return true
				}
			}
		}
		return false
	default:
		for key := range valueMap {
			if key == checkValue {
				return true
			}
		}
		return false
	}
}

func (attr *Attribute) NotContains(checkValue interface{}, equalityOptions ...EqualityOption) bool {
	return !attr.Contains(checkValue, equalityOptions...)
}

func (attr *Attribute) Contains(checkValue interface{}, equalityOptions ...EqualityOption) bool {
	if attr == nil {
		return false
	}
	ignoreCase := false
	for _, option := range equalityOptions {
		if option == IgnoreCase {
			ignoreCase = true
		}
	}
	val := attr.Value()
	if val.IsNull() {
		return false
	}

	if val.Type().IsObjectType() || val.Type().IsMapType() {
		return attr.mapContains(checkValue, val)
	}

	stringToLookFor := fmt.Sprintf("%v", checkValue)

	if val.Type().IsListType() || val.Type().IsTupleType() {
		return attr.listContains(val, stringToLookFor, ignoreCase)
	}

	if ignoreCase && containsIgnoreCase(val.AsString(), stringToLookFor) {
		return true
	}

	return strings.Contains(val.AsString(), stringToLookFor)
}

func containsIgnoreCase(left, substring string) bool {
	return strings.Contains(strings.ToLower(left), strings.ToLower(substring))
}

func (attr *Attribute) StartsWith(prefix interface{}) bool {
	if attr == nil {
		return false
	}
	if attr.Value().Type() == cty.String {
		return strings.HasPrefix(attr.Value().AsString(), fmt.Sprintf("%v", prefix))
	}
	return false
}

func (attr *Attribute) EndsWith(suffix interface{}) bool {
	if attr == nil {
		return false
	}
	if attr.Value().Type() == cty.String {
		return strings.HasSuffix(attr.Value().AsString(), fmt.Sprintf("%v", suffix))
	}
	return false
}

type EqualityOption int

const (
	IgnoreCase EqualityOption = iota
)

func (attr *Attribute) Equals(checkValue interface{}, equalityOptions ...EqualityOption) bool {
	if attr == nil {
		return false
	}
	if attr.Value().Type() == cty.String {
		for _, option := range equalityOptions {
			if option == IgnoreCase {
				return strings.EqualFold(strings.ToLower(attr.Value().AsString()), strings.ToLower(fmt.Sprintf("%v", checkValue)))
			}
		}
		result := strings.EqualFold(attr.Value().AsString(), fmt.Sprintf("%v", checkValue))
		return result
	}
	if attr.Value().Type() == cty.Bool {
		return attr.Value().True() == checkValue
	}
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting number for equality check. %s", err)
			return false
		}
		return attr.Value().RawEquals(checkNumber)
	}

	return false
}

func (attr *Attribute) NotEqual(checkValue interface{}, equalityOptions ...EqualityOption) bool {
	return !attr.Equals(checkValue, equalityOptions...)
}

func (attr *Attribute) RegexMatches(pattern interface{}) bool {
	if attr == nil {
		return false
	}
	patternVal := fmt.Sprintf("%v", pattern)
	re, err := regexp.Compile(patternVal)
	if err != nil {
		debug.Log("an error occurred while compiling the regex: %s", err)
		return false
	}
	if attr.Value().Type() == cty.String {
		match := re.MatchString(attr.Value().AsString())
		return match
	}
	return false
}

func (attr *Attribute) IsNotAny(options ...interface{}) bool {
	return !attr.IsAny(options...)
}

func (attr *Attribute) IsAny(options ...interface{}) bool {
	if attr == nil {
		return false
	}
	if attr.Value().Type() == cty.String {
		value := attr.Value().AsString()
		for _, option := range options {
			if option == value {
				return true
			}
		}
	}
	if attr.Value().Type() == cty.Number {
		for _, option := range options {
			checkValue, err := gocty.ToCtyValue(option, cty.Number)
			if err != nil {
				debug.Log("Error converting number for equality check. %s", err)
				return false
			}
			if attr.Value().RawEquals(checkValue) {
				return true
			}
		}
	}
	return false
}

func (attr *Attribute) IsNone(options ...interface{}) bool {
	if attr == nil {
		return false
	}
	if attr.Value().Type() == cty.String {
		for _, option := range options {
			if option == attr.Value().AsString() {
				return false
			}
		}
	}
	if attr.Value().Type() == cty.Number {
		for _, option := range options {
			checkValue, err := gocty.ToCtyValue(option, cty.Number)
			if err != nil {
				debug.Log("Error converting number for equality check. %s", err)
				return false
			}
			if attr.Value().RawEquals(checkValue) {
				return false
			}

		}
	}

	return true
}

func (attr *Attribute) IsTrue() bool {
	if attr == nil {
		return false
	}
	switch attr.Value().Type() {
	case cty.Bool:
		return attr.Value().True()
	case cty.String:
		val := attr.Value().AsString()
		val = strings.Trim(val, "\"")
		return strings.ToLower(val) == "true"
	case cty.Number:
		val := attr.Value().AsBigFloat()
		f, _ := val.Float64()
		return f > 0
	}
	return false
}

func (attr *Attribute) IsFalse() bool {
	if attr == nil {
		return false
	}
	switch attr.Value().Type() {
	case cty.Bool:
		return attr.Value().False()
	case cty.String:
		val := attr.Value().AsString()
		val = strings.Trim(val, "\"")
		return strings.ToLower(val) == "false"
	case cty.Number:
		val := attr.Value().AsBigFloat()
		f, _ := val.Float64()
		return f == 0
	}
	return false
}

func (attr *Attribute) IsEmpty() bool {
	if attr == nil {
		return false
	}
	if attr.Value().Type() == cty.String {
		return len(attr.Value().AsString()) == 0
	}
	if attr.Type().IsListType() || attr.Type().IsTupleType() {
		return len(attr.Value().AsValueSlice()) == 0
	}
	if attr.Type().IsMapType() || attr.Type().IsObjectType() {
		return len(attr.Value().AsValueMap()) == 0
	}
	if attr.Value().Type() == cty.Number {
		// a number can't ever be empty
		return false
	}
	if attr.Value().IsNull() {
		return attr.isNullAttributeEmpty()
	}
	return true
}

func (attr *Attribute) IsNotEmpty() bool {
	return !attr.IsEmpty()
}

func (attr *Attribute) isNullAttributeEmpty() bool {
	if attr == nil {
		return false
	}
	switch t := attr.hclAttribute.Expr.(type) {
	case *hclsyntax.FunctionCallExpr, *hclsyntax.ScopeTraversalExpr,
		*hclsyntax.ConditionalExpr, *hclsyntax.LiteralValueExpr:
		return false
	case *hclsyntax.TemplateExpr:
		// walk the parts of the expression to ensure that it has a literal value
		for _, p := range t.Parts {
			switch pt := p.(type) {
			case *hclsyntax.LiteralValueExpr:
				if pt != nil && !pt.Val.IsNull() {
					return false
				}
			case *hclsyntax.ScopeTraversalExpr:
				return false
			}
		}
	}
	return true
}

func (attr *Attribute) MapValue(mapKey string) cty.Value {
	if attr == nil {
		return cty.NilVal
	}
	if attr.Type().IsObjectType() || attr.Type().IsMapType() {
		attrMap := attr.Value().AsValueMap()
		for key, value := range attrMap {
			if key == mapKey {
				return value
			}
		}
	}
	return cty.NilVal
}

func (attr *Attribute) LessThan(checkValue interface{}) bool {
	if attr == nil {
		return false
	}
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting number for equality check. %s", err)
			return false
		}

		return attr.Value().LessThan(checkNumber).True()
	}
	return false
}

func (attr *Attribute) LessThanOrEqualTo(checkValue interface{}) bool {
	if attr == nil {
		return false
	}
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting number for equality check. %s", err)
			return false
		}

		return attr.Value().LessThanOrEqualTo(checkNumber).True()
	}
	return false
}

func (attr *Attribute) GreaterThan(checkValue interface{}) bool {
	if attr == nil {
		return false
	}
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting number for equality check. %s", err)
			return false
		}

		return attr.Value().GreaterThan(checkNumber).True()
	}
	return false
}

func (attr *Attribute) GreaterThanOrEqualTo(checkValue interface{}) bool {
	if attr == nil {
		return false
	}
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting number for equality check. %s", err)
			return false
		}

		return attr.Value().GreaterThanOrEqualTo(checkNumber).True()
	}
	return false
}

func (attr *Attribute) IsDataBlockReference() bool {
	if attr == nil {
		return false
	}
	switch t := attr.hclAttribute.Expr.(type) {
	case *hclsyntax.ScopeTraversalExpr:
		split := t.Traversal.SimpleSplit()
		return split.Abs.RootName() == "data"
	}
	return false
}

func createDotReferenceFromTraversal(parentRef string, traversals ...hcl.Traversal) (*Reference, error) {
	var refParts []string
	var key cty.Value
	for _, x := range traversals {
		for _, p := range x {
			switch part := p.(type) {
			case hcl.TraverseRoot:
				refParts = append(refParts, part.Name)
			case hcl.TraverseAttr:
				refParts = append(refParts, part.Name)
			case hcl.TraverseIndex:
				key = part.Key
			}
		}
	}
	ref, err := newReference(refParts, parentRef)
	if err != nil {
		return nil, err
	}
	if !key.IsNull() {
		ref.SetKey(key)
	}
	return ref, nil
}

func (attr *Attribute) SingleReference() (*Reference, error) {
	if attr == nil {
		return nil, fmt.Errorf("attribute is nil")
	}

	switch t := attr.hclAttribute.Expr.(type) {
	case *hclsyntax.RelativeTraversalExpr:
		switch s := t.Source.(type) {
		case *hclsyntax.IndexExpr:
			collectionRef, err := createDotReferenceFromTraversal(attr.module, s.Collection.Variables()...)
			if err != nil {
				return nil, err
			}
			key, _ := s.Key.Value(attr.ctx.Inner())
			collectionRef.SetKey(key)
			return collectionRef, nil
		default:
			return createDotReferenceFromTraversal(attr.module, t.Source.Variables()...)
		}
	case *hclsyntax.ScopeTraversalExpr:
		return createDotReferenceFromTraversal(attr.module, t.Traversal)
	case *hclsyntax.TemplateExpr:
		refs := attr.referencesInTemplate()
		if len(refs) == 0 {
			return nil, fmt.Errorf("no references in template")
		}
		return refs[0], nil
	default:
		return nil, fmt.Errorf("not a reference: no scope traversal")
	}
}

func (attr *Attribute) ReferencesBlock(b *Block) bool {
	if attr == nil {
		return false
	}
	for _, ref := range attr.AllReferences() {
		if ref.RefersTo(b.GetMetadata().Reference()) {
			return true
		}
	}
	return false
}

func (attr *Attribute) AllReferences(blocks ...*Block) []*Reference {
	if attr == nil {
		return nil
	}
	var refs []*Reference
	refs = append(refs, attr.referencesInTemplate()...)
	refs = append(refs, attr.referencesInConditional()...)
	ref, err := attr.SingleReference()
	if err == nil {
		refs = append(refs, ref)
	}
	for _, block := range blocks {
		for _, ref := range refs {
			if ref.TypeLabel() == "each" && block.HasChild("for_each") {
				refs = append(refs, block.GetAttribute("for_each").AllReferences()...)
			}
		}
	}
	return refs
}

func (attr *Attribute) referencesInTemplate() []*Reference {
	if attr == nil {
		return nil
	}
	var refs []*Reference
	switch t := attr.hclAttribute.Expr.(type) {
	case *hclsyntax.TemplateExpr:
		for _, part := range t.Parts {
			ref, err := createDotReferenceFromTraversal(attr.module, part.Variables()...)
			if err != nil {
				continue
			}
			refs = append(refs, ref)
		}
	case *hclsyntax.TupleConsExpr:
		ref, err := createDotReferenceFromTraversal(attr.module, t.Variables()...)
		if err == nil {
			refs = append(refs, ref)
		}
	}
	return refs
}

func (attr *Attribute) referencesInConditional() []*Reference {
	if attr == nil {
		return nil
	}
	var refs []*Reference
	switch t := attr.hclAttribute.Expr.(type) {
	case *hclsyntax.ConditionalExpr:
		if ref, err := createDotReferenceFromTraversal(attr.module, t.TrueResult.Variables()...); err == nil {
			refs = append(refs, ref)
		}
		if ref, err := createDotReferenceFromTraversal(attr.module, t.FalseResult.Variables()...); err == nil {
			refs = append(refs, ref)
		}
		if ref, err := createDotReferenceFromTraversal(attr.module, t.Condition.Variables()...); err == nil {
			refs = append(refs, ref)
		}
	}
	return refs
}

func (attr *Attribute) IsResourceBlockReference(resourceType string) bool {
	if attr == nil {
		return false
	}
	switch t := attr.hclAttribute.Expr.(type) {
	case *hclsyntax.ScopeTraversalExpr:
		split := t.Traversal.SimpleSplit()
		return split.Abs.RootName() == resourceType
	}
	return false
}

func (attr *Attribute) References(r types.Reference) bool {
	if attr == nil {
		return false
	}
	for _, ref := range attr.AllReferences() {
		if ref.RefersTo(r) {
			return true
		}
	}
	return false
}

func getRawValue(value cty.Value) interface{} {
	typeName := value.Type().FriendlyName()

	switch typeName {
	case "string":
		return value.AsString()
	case "number":
		return value.AsBigFloat()
	case "bool":
		return value.True()
	}

	return value
}

func (attr *Attribute) IsNil() bool {
	return attr == nil
}

func (attr *Attribute) IsNotNil() bool {
	return !attr.IsNil()
}

func (attr *Attribute) HasIntersect(checkValues ...interface{}) bool {
	if !attr.Type().IsListType() && !attr.Type().IsTupleType() {
		return false
	}

	for _, item := range checkValues {
		if attr.Contains(item) {
			return true
		}
	}
	return false

}
