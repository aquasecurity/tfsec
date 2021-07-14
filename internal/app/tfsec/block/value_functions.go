package block

const (
	functionNameKey = "action"
	valueNameKey    = "value"
)

var functions = map[string]func(interface{}, interface{}) bool{
	"isAny":  isAny,
	"isNone": isNone,
}

func evaluate(criteriaValue interface{}, testValue interface{}) bool {
	switch t := criteriaValue.(type) {
	case map[interface{}]interface{}:
		if t[functionNameKey] != nil {
			return executeFunction(t[functionNameKey].(string), t[valueNameKey], testValue)
		}
	case map[string]interface{}:
		if t[functionNameKey] != nil {
			return executeFunction(t[functionNameKey].(string), t[valueNameKey], testValue)
		}
	default:
		return t == testValue
	}
	return false
}

func executeFunction(functionName string, criteriaValues, testValue interface{}) bool {
	if functions[functionName] != nil {
		return functions[functionName](criteriaValues, testValue)
	}
	return false
}

func isAny(criteriaValues interface{}, testValue interface{}) bool {
	switch t := criteriaValues.(type) {
	case []interface{}:
		for _, v := range t {
			if v == testValue {
				return true
			}
		}
	case []string:
		for _, v := range t {
			if v == testValue.(string) {
				return true
			}
		}
	}
	return false
}

func isNone(criteriaValues interface{}, testValue interface{}) bool {
	return !isAny(criteriaValues, testValue)
}
