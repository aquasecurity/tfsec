package definition

type Metadata struct {
	Filepath  string
	StartLine int
	EndLine   int
	IsDefined bool
}

func NewMetadata(filepath string, startline, endline int) Metadata {
	return Metadata{
		Filepath:  filepath,
		StartLine: startline,
		EndLine:   endline,
		IsDefined: true,
	}

}

//type AwsSecurityGroupRule struct {
//securityGroupId string
//}

//type AwsSecurityGroup struct {
//id string
//rules []AwsSecurityGroupRule
//}

//type AwsLoadBalancer struct {
//securityGroups []AwsSecurityGroup
//}

//type AwsInstance struct {
//securityGroups []AwsSecurityGroup
//}

//func (*s AwsSecurityGroup) GetSecurityGroupRules(id string) []AwsSecurityGroupRule {
//var groupRules []AwsSecurityGroupRule

//for _, sgr := range context.AWS.SecurityGroupRules() {
//if sgr.securityGroupId == id {
//groupRules = append(groupRules, sgr)
//}
//}

//return groupRules
//}

//type VPC interface {
//GetSecurityGroups()
//GetSecurityGroupRules()
//}

//type AWS struct {
//Vpc VPC
//S3  S3
//}

//type Context struct {
//AWS AWS
//}

//type SG {
//Description StringValue
//Rules []SGR
//}

//type VPCTranslator struct {
//modules []block.Module
//}

//func NewVPCTranslator(modules []block.Module) {
//return VPCTranslator{
//modules: modules,
//}
//}

//func (t *VPCTranslator) GetSecurityGroupRules() {
//var rules []SGR
//for _, module := range t.modules {
//for _, block := range module.GetResourcesByType("aws_vpc_security_group_rule") {
//rules = append(rules, translateSGR(block))
//}
//}
//}

//func translateSGR(block block.Block) SGR {
//return SGR{
//Description: translateToValue(blockGetAttribute("description")),
//}
//}

//func translateToValue(attr Attribute) Value {
//return Value{
//Reference: attr.Reference(),
//Value: attr.Value(),
//}
//}
