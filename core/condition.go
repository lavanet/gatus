package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/TwiN/gatus/v5/jsonpath"
	"github.com/TwiN/gatus/v5/pattern"
)

// Placeholders
const (
	// StatusPlaceholder is a placeholder for a HTTP status.
	//
	// Values that could replace the placeholder: 200, 404, 500, ...
	StatusPlaceholder = "[STATUS]"

	// IPPlaceholder is a placeholder for an IP.
	//
	// Values that could replace the placeholder: 127.0.0.1, 10.0.0.1, ...
	IPPlaceholder = "[IP]"

	// DNSRCodePlaceholder is a placeholder for DNS_RCODE
	//
	// Values that could replace the placeholder: NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED
	DNSRCodePlaceholder = "[DNS_RCODE]"

	// ResponseTimePlaceholder is a placeholder for the request response time, in milliseconds.
	//
	// Values that could replace the placeholder: 1, 500, 1000, ...
	ResponseTimePlaceholder = "[RESPONSE_TIME]"

	// BodyPlaceholder is a placeholder for the body of the response
	//
	// Values that could replace the placeholder: {}, {"data":{"name":"john"}}, ...
	BodyPlaceholder = "[BODY]"

	// ConnectedPlaceholder is a placeholder for whether a connection was successfully established.
	//
	// Values that could replace the placeholder: true, false
	ConnectedPlaceholder = "[CONNECTED]"

	// CertificateExpirationPlaceholder is a placeholder for the duration before certificate expiration, in milliseconds.
	//
	// Values that could replace the placeholder: 4461677039 (~52 days)
	CertificateExpirationPlaceholder = "[CERTIFICATE_EXPIRATION]"

	// DomainExpirationPlaceholder is a placeholder for the duration before the domain expires, in milliseconds.
	DomainExpirationPlaceholder = "[DOMAIN_EXPIRATION]"
)

// Functions
const (
	// LengthFunctionPrefix is the prefix for the length function
	//
	// Usage: len([BODY].articles) == 10, len([BODY].name) > 5
	LengthFunctionPrefix = "len("

	// HasFunctionPrefix is the prefix for the has function
	//
	// Usage: has([BODY].errors) == true
	HasFunctionPrefix = "has("

	// PatternFunctionPrefix is the prefix for the pattern function
	//
	// Usage: [IP] == pat(192.168.*.*)
	PatternFunctionPrefix = "pat("

	//
	// For block number comparison
	BlockNumFunctionPrefix = "blockNum("

	// AnyFunctionPrefix is the prefix for the any function
	//
	// Usage: [IP] == any(1.1.1.1, 1.0.0.1)
	AnyFunctionPrefix = "any("

	// FunctionSuffix is the suffix for all functions
	FunctionSuffix = ")"
)

// Other constants
const (
	// InvalidConditionElementSuffix is the suffix that will be appended to an invalid condition
	InvalidConditionElementSuffix = "(INVALID)"

	// maximumLengthBeforeTruncatingWhenComparedWithPattern is the maximum length an element being compared to a
	// pattern can have.
	//
	// This is only used for aesthetic purposes; it does not influence whether the condition evaluation results in a
	// success or a failure
	maximumLengthBeforeTruncatingWhenComparedWithPattern = 25
)

// Condition is a condition that needs to be met in order for an Endpoint to be considered healthy.
type Condition string

// Validate checks if the Condition is valid
func (c Condition) Validate() error {
	r := &Result{}
	c.evaluate(r, false)
	if len(r.Errors) != 0 {
		return errors.New(r.Errors[0])
	}
	return nil
}

// evaluate the Condition with the Result of the health check
func (c Condition) evaluate(result *Result, dontResolveFailedConditions bool) bool {
	condition := string(c)
	success := false
	conditionToDisplay := condition
	if strings.Contains(condition, " == ") {
		parameters, resolvedParameters := sanitizeAndResolve(strings.Split(condition, " == "), result)
		success = isEqual(result, resolvedParameters[0], resolvedParameters[1])
		if !success && !dontResolveFailedConditions {
			conditionToDisplay = prettify(parameters, resolvedParameters, "==")
		}
	} else if strings.Contains(condition, " != ") {
		parameters, resolvedParameters := sanitizeAndResolve(strings.Split(condition, " != "), result)
		success = !isEqual(result, resolvedParameters[0], resolvedParameters[1])
		if !success && !dontResolveFailedConditions {
			conditionToDisplay = prettify(parameters, resolvedParameters, "!=")
		}
	} else if strings.Contains(condition, " <= ") {
		parameters, resolvedParameters := sanitizeAndResolveNumerical(strings.Split(condition, " <= "), result)
		success = resolvedParameters[0] <= resolvedParameters[1]
		if !success && !dontResolveFailedConditions {
			conditionToDisplay = prettifyNumericalParameters(parameters, resolvedParameters, "<=")
		}
	} else if strings.Contains(condition, " >= ") {
		parameters, resolvedParameters := sanitizeAndResolveNumerical(strings.Split(condition, " >= "), result)
		success = resolvedParameters[0] >= resolvedParameters[1]
		if !success && !dontResolveFailedConditions {
			conditionToDisplay = prettifyNumericalParameters(parameters, resolvedParameters, ">=")
		}
	} else if strings.Contains(condition, " > ") {
		parameters, resolvedParameters := sanitizeAndResolveNumerical(strings.Split(condition, " > "), result)
		success = resolvedParameters[0] > resolvedParameters[1]
		if !success && !dontResolveFailedConditions {
			conditionToDisplay = prettifyNumericalParameters(parameters, resolvedParameters, ">")
		}
	} else if strings.Contains(condition, " < ") {
		parameters, resolvedParameters := sanitizeAndResolveNumerical(strings.Split(condition, " < "), result)
		success = resolvedParameters[0] < resolvedParameters[1]
		if !success && !dontResolveFailedConditions {
			conditionToDisplay = prettifyNumericalParameters(parameters, resolvedParameters, "<")
		}
	} else {
		result.AddError(fmt.Sprintf("invalid condition: %s", condition))
		return false
	}
	if !success {
		//log.Printf("[Condition][evaluate] Condition '%s' did not succeed because '%s' is false", condition, condition)
	}
	result.ConditionResults = append(result.ConditionResults, &ConditionResult{Condition: conditionToDisplay, Success: success})
	return success
}

// hasBodyPlaceholder checks whether the condition has a BodyPlaceholder
// Used for determining whether the response body should be read or not
func (c Condition) hasBodyPlaceholder() bool {
	return strings.Contains(string(c), BodyPlaceholder)
}

// hasDomainExpirationPlaceholder checks whether the condition has a DomainExpirationPlaceholder
// Used for determining whether a whois operation is necessary
func (c Condition) hasDomainExpirationPlaceholder() bool {
	return strings.Contains(string(c), DomainExpirationPlaceholder)
}

// hasIPPlaceholder checks whether the condition has an IPPlaceholder
// Used for determining whether an IP lookup is necessary
func (c Condition) hasIPPlaceholder() bool {
	return strings.Contains(string(c), IPPlaceholder)
}

func decodeHex(hex interface{}) (int64, error) {
	hexStr := fmt.Sprintf("%v", hex)
	value, err := strconv.ParseInt(hexStr[2:], 16, 64)
	if err != nil {
		return 0, err
	}
	return value, nil
}

type cosmosBlock2 struct {
	Height string `json:"height"`
}

type cosmosBlock1 struct {
	Header cosmosBlock2 `json:"header"`
}

type cosmosBlock struct {
	Block cosmosBlock1 `json:"block"`
}

func ethBlockNum(result *Result, compareRpcs []string, first string) (int64, int64, bool) {
	var firstI, secondI int64

	firstI, err := decodeHex(first)
	if err != nil {
		result.AddError(err.Error())
		return 0, 0, false
	}

	for _, compareRpc := range compareRpcs {
		resp, err := http.Post(
			compareRpc,
			"application/json",
			bytes.NewBuffer([]byte(`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`)),
		)
		if err != nil {
			continue
		}

		var res map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&res)
		if err != nil {
			continue
		}

		secondI, err = decodeHex(res["result"])
		if err != nil {
			continue
		}
	}
	if secondI == 0 {
		result.AddError("error grabbing block from external rpc")
		return 0, 0, false
	}

	return firstI, secondI, true
}

func cosmosBlockNum(result *Result, compareRpcs []string, first string) (int64, int64, bool) {
	var firstI, secondI int64
	firstI, err := strconv.ParseInt(first, 10, 64)
	if err != nil {
		result.AddError(err.Error())
		return 0, 0, false
	}

	for _, compareRpc := range compareRpcs {
		resp, err := http.Get(compareRpc)
		if err != nil {
			continue
		}

		var res cosmosBlock
		err = json.NewDecoder(resp.Body).Decode(&res)
		if err != nil {
			continue
		}

		secondI, err = strconv.ParseInt(res.Block.Header.Height, 10, 64)
		if err != nil {
			continue
		}
	}
	if secondI == 0 {
		result.AddError("error grabbing block from external rpc")
		return 0, 0, false
	}

	return firstI, secondI, true
}

func starknetBlockNum(result *Result, compareRpcs []string, first string) (int64, int64, bool) {
	var firstI, secondI int64
	firstI, err := strconv.ParseInt(first, 10, 64)
	if err != nil {
		result.AddError(err.Error())
		return 0, 0, false
	}

	for _, compareRpc := range compareRpcs {
		resp, err := http.Get(compareRpc)
		if err != nil {
			continue
		}

		var res map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&res)
		if err != nil {
			continue
		}

		secondStr := fmt.Sprintf("%v", res["block_number"])
		secondI, err = strconv.ParseInt(secondStr, 10, 64)
		if err != nil {
			continue
		}
	}
	if secondI == 0 {
		result.AddError("error grabbing block from external rpc")
		return 0, 0, false
	}

	return firstI, secondI, true
}

func aptosBlockNum(result *Result, compareRpcs []string, first string) (int64, int64, bool) {
	var firstI, secondI int64

	firstI, err := strconv.ParseInt(first, 10, 64)
	if err != nil {
		result.AddError(err.Error())
		return 0, 0, false
	}

	for _, compareRpc := range compareRpcs {
		resp, err := http.Get(compareRpc)
		if err != nil {
			continue
		}

		var res map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&res)
		if err != nil {
			continue
		}

		secondStr := fmt.Sprintf("%v", res["block_height"])
		secondI, err = strconv.ParseInt(secondStr, 10, 64)
		if err != nil {
			continue
		}
	}
	if secondI == 0 {
		result.AddError("error grabbing block from external rpc")
		return 0, 0, false
	}

	return firstI, secondI, true
}

func blockNum(result *Result, first, second string) bool {
	//
	// Skip evaluation on init (or else it breaks)
	if strings.Contains(first, InvalidConditionElementSuffix) {
		return false
	}

	args := strings.Split(second, ",")
	if len(args) < 3 {
		result.AddError("Bad configuration! " + second)
		return false
	}
	deltaThreshold, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		result.AddError(err.Error())
		return false
	}
	var firstI, secondI int64
	chainType := args[1]

	compareRpc := args[2:]

	switch chainType {
	case "eth":
		var isOk bool
		firstI, secondI, isOk = ethBlockNum(result, compareRpc, first)
		if !isOk {
			return isOk
		}

	case "cosmos":
		var isOk bool
		firstI, secondI, isOk = cosmosBlockNum(result, compareRpc, first)
		if !isOk {
			return isOk
		}

	case "starknet":
		var isOk bool
		firstI, secondI, isOk = starknetBlockNum(result, compareRpc, first)
		if !isOk {
			return isOk
		}

	case "aptos":
		var isOk bool
		firstI, secondI, isOk = aptosBlockNum(result, compareRpc, first)
		if !isOk {
			return isOk
		}
	default:
		result.AddError("bad chainType " + chainType)
		return false

	}

	result.AddError(fmt.Sprintf("rpc: %d, reference: %d", firstI, secondI))
	return !(absInt(secondI-firstI) > deltaThreshold)
}

func absInt(number int64) int64 {
	if number < 0 {
		return -number
	} else {
		return number
	}
}

// isEqual compares two strings.
//
// Supports the "pat" and the "any" functions.
// i.e. if one of the parameters starts with PatternFunctionPrefix and ends with FunctionSuffix, it will be treated like
// a pattern.
func isEqual(result *Result, first, second string) bool {
	firstHasFunctionSuffix := strings.HasSuffix(first, FunctionSuffix)
	secondHasFunctionSuffix := strings.HasSuffix(second, FunctionSuffix)
	if firstHasFunctionSuffix || secondHasFunctionSuffix {
		var isFirstPattern, isSecondPattern bool
		if strings.HasPrefix(first, PatternFunctionPrefix) && firstHasFunctionSuffix {
			isFirstPattern = true
			first = strings.TrimSuffix(strings.TrimPrefix(first, PatternFunctionPrefix), FunctionSuffix)
		}
		if strings.HasPrefix(second, PatternFunctionPrefix) && secondHasFunctionSuffix {
			isSecondPattern = true
			second = strings.TrimSuffix(strings.TrimPrefix(second, PatternFunctionPrefix), FunctionSuffix)
		}
		if strings.HasPrefix(second, BlockNumFunctionPrefix) && secondHasFunctionSuffix {
			second = strings.TrimSuffix(strings.TrimPrefix(second, BlockNumFunctionPrefix), FunctionSuffix)
			return blockNum(result, first, second)
		}

		if isFirstPattern && !isSecondPattern {
			return pattern.Match(first, second)
		} else if !isFirstPattern && isSecondPattern {
			return pattern.Match(second, first)
		}
		var isFirstAny, isSecondAny bool
		if strings.HasPrefix(first, AnyFunctionPrefix) && firstHasFunctionSuffix {
			isFirstAny = true
			first = strings.TrimSuffix(strings.TrimPrefix(first, AnyFunctionPrefix), FunctionSuffix)
		}
		if strings.HasPrefix(second, AnyFunctionPrefix) && secondHasFunctionSuffix {
			isSecondAny = true
			second = strings.TrimSuffix(strings.TrimPrefix(second, AnyFunctionPrefix), FunctionSuffix)
		}
		if isFirstAny && !isSecondAny {
			options := strings.Split(first, ",")
			for _, option := range options {
				if strings.TrimSpace(option) == second {
					return true
				}
			}
			return false
		} else if !isFirstAny && isSecondAny {
			options := strings.Split(second, ",")
			for _, option := range options {
				if strings.TrimSpace(option) == first {
					return true
				}
			}
			return false
		}
	}
	return first == second
}

// sanitizeAndResolve sanitizes and resolves a list of elements and returns the list of parameters as well as a list
// of resolved parameters
func sanitizeAndResolve(elements []string, result *Result) ([]string, []string) {
	parameters := make([]string, len(elements))
	resolvedParameters := make([]string, len(elements))
	body := strings.TrimSpace(string(result.body))
	for i, element := range elements {
		element = strings.TrimSpace(element)
		parameters[i] = element
		switch strings.ToUpper(element) {
		case StatusPlaceholder:
			element = strconv.Itoa(result.HTTPStatus)
		case IPPlaceholder:
			element = result.IP
		case ResponseTimePlaceholder:
			element = strconv.Itoa(int(result.Duration.Milliseconds()))
		case BodyPlaceholder:
			element = body
		case DNSRCodePlaceholder:
			element = result.DNSRCode
		case ConnectedPlaceholder:
			element = strconv.FormatBool(result.Connected)
		case CertificateExpirationPlaceholder:
			element = strconv.FormatInt(result.CertificateExpiration.Milliseconds(), 10)
		case DomainExpirationPlaceholder:
			element = strconv.FormatInt(result.DomainExpiration.Milliseconds(), 10)
		default:
			// if contains the BodyPlaceholder, then evaluate json path
			if strings.Contains(element, BodyPlaceholder) {
				checkingForLength := false
				checkingForExistence := false
				if strings.HasPrefix(element, LengthFunctionPrefix) && strings.HasSuffix(element, FunctionSuffix) {
					checkingForLength = true
					element = strings.TrimSuffix(strings.TrimPrefix(element, LengthFunctionPrefix), FunctionSuffix)
				}
				if strings.HasPrefix(element, HasFunctionPrefix) && strings.HasSuffix(element, FunctionSuffix) {
					checkingForExistence = true
					element = strings.TrimSuffix(strings.TrimPrefix(element, HasFunctionPrefix), FunctionSuffix)
				}
				resolvedElement, resolvedElementLength, err := jsonpath.Eval(strings.TrimPrefix(strings.TrimPrefix(element, BodyPlaceholder), "."), result.body)
				if checkingForExistence {
					if err != nil {
						element = "false"
					} else {
						element = "true"
					}
				} else {
					if err != nil {
						if err.Error() != "unexpected end of JSON input" {
							result.AddError(err.Error())
						}
						if checkingForLength {
							element = LengthFunctionPrefix + element + FunctionSuffix + " " + InvalidConditionElementSuffix
						} else {
							element = element + " " + InvalidConditionElementSuffix
						}
					} else {
						if checkingForLength {
							element = strconv.Itoa(resolvedElementLength)
						} else {
							element = resolvedElement
						}
					}
				}
			}
		}
		resolvedParameters[i] = element
	}
	return parameters, resolvedParameters
}

func sanitizeAndResolveNumerical(list []string, result *Result) (parameters []string, resolvedNumericalParameters []int64) {
	parameters, resolvedParameters := sanitizeAndResolve(list, result)
	for _, element := range resolvedParameters {
		if duration, err := time.ParseDuration(element); duration != 0 && err == nil {
			resolvedNumericalParameters = append(resolvedNumericalParameters, duration.Milliseconds())
		} else if number, err := strconv.ParseInt(element, 10, 64); err != nil {
			// Default to 0 if the string couldn't be converted to an integer
			resolvedNumericalParameters = append(resolvedNumericalParameters, 0)
		} else {
			resolvedNumericalParameters = append(resolvedNumericalParameters, number)
		}
	}
	return parameters, resolvedNumericalParameters
}

func prettifyNumericalParameters(parameters []string, resolvedParameters []int64, operator string) string {
	return prettify(parameters, []string{strconv.Itoa(int(resolvedParameters[0])), strconv.Itoa(int(resolvedParameters[1]))}, operator)
}

// prettify returns a string representation of a condition with its parameters resolved between parentheses
func prettify(parameters []string, resolvedParameters []string, operator string) string {
	// Since, in the event of an invalid path, the resolvedParameters also contain the condition itself,
	// we'll return the resolvedParameters as-is.
	if strings.HasSuffix(resolvedParameters[0], InvalidConditionElementSuffix) || strings.HasSuffix(resolvedParameters[1], InvalidConditionElementSuffix) {
		return resolvedParameters[0] + " " + operator + " " + resolvedParameters[1]
	}
	// If using the pattern function, truncate the parameter it's being compared to if said parameter is long enough
	if strings.HasPrefix(parameters[0], PatternFunctionPrefix) && strings.HasSuffix(parameters[0], FunctionSuffix) && len(resolvedParameters[1]) > maximumLengthBeforeTruncatingWhenComparedWithPattern {
		resolvedParameters[1] = fmt.Sprintf("%.25s...(truncated)", resolvedParameters[1])
	}
	if strings.HasPrefix(parameters[1], PatternFunctionPrefix) && strings.HasSuffix(parameters[1], FunctionSuffix) && len(resolvedParameters[0]) > maximumLengthBeforeTruncatingWhenComparedWithPattern {
		resolvedParameters[0] = fmt.Sprintf("%.25s...(truncated)", resolvedParameters[0])
	}
	// First element is a placeholder
	if parameters[0] != resolvedParameters[0] && parameters[1] == resolvedParameters[1] {
		return parameters[0] + " (" + resolvedParameters[0] + ") " + operator + " " + parameters[1]
	}
	// Second element is a placeholder
	if parameters[0] == resolvedParameters[0] && parameters[1] != resolvedParameters[1] {
		return parameters[0] + " " + operator + " " + parameters[1] + " (" + resolvedParameters[1] + ")"
	}
	// Both elements are placeholders...?
	if parameters[0] != resolvedParameters[0] && parameters[1] != resolvedParameters[1] {
		return parameters[0] + " (" + resolvedParameters[0] + ") " + operator + " " + parameters[1] + " (" + resolvedParameters[1] + ")"
	}
	// Neither elements are placeholders
	return parameters[0] + " " + operator + " " + parameters[1]
}
