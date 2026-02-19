package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/everettraven/oidc-external-sources-webhook/pkg/internal/thirdparty/kubernetes/apiserver/pkg/apis/apiserver"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/interpreter"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
)

type ExternalClaimsCompatibleCompiler interface {
	CompileExternalSourceExpression(expressionAccessor authenticationcel.ExpressionAccessor) (authenticationcel.CompilationResult, error)
}

func NewExternalClaimsResolver(externalClaimSource apiserver.ExternalClaimsSource, compiler authenticationcel.Compiler) (*externalClaimsResolver, error) {
	// TODO: realistically, this case should never happen - I'm just trying to fork less code for PoC
	// purposes. The _correct_ approach here is to also fork the interfaces for the authenticationcel.Compiler.
	externalClaimsCompiler, ok := compiler.(ExternalClaimsCompatibleCompiler)
	if !ok {
		return nil, fmt.Errorf("incompatible compiler implementation")
	}

	out := &externalClaimsResolver{}

	out.clientAuthentication = clientAuthenticationForAuthentication(externalClaimSource.Authentication)

	out.tls = TLS{
		certificateAuthority: externalClaimSource.TLS.CA,
	}

	for _, source := range externalClaimSource.Sources {

		pathExpressionCompiled, err := compiler.CompileClaimsExpression(&authenticationcel.ClaimMappingExpression{
			Expression: source.URL.PathExpression,
		})
		if err != nil {
			return nil, fmt.Errorf("compiling path expression %q: %w", source.URL.PathExpression, err)
		}

		mappings := make(map[string]ExternalSourceResponseMapper)

		for _, mapping := range source.Mappings {
			mappingExpressionCompiled, err := externalClaimsCompiler.CompileExternalSourceExpression(&authenticationcel.ClaimMappingExpression{
				Expression: mapping.Expression,
			})
			if err != nil {
				return nil, fmt.Errorf("compiling mapping expression %q: %w", mapping.Expression, err)
			}

			mappings[mapping.Name] = &mapper{
				result: mappingExpressionCompiled,
			}
		}

		ec := externalClaim{
			celMapper: externalClaimCELMapper{
				URL: urlCELMapper{
					Base:           source.URL.Base,
					PathExpression: authenticationcel.NewClaimsMapper([]authenticationcel.CompilationResult{pathExpressionCompiled}),
				},
				Mappings: mappings,
			},
		}
		out.claims = append(out.claims, ec)
	}

	return out, nil
}

type mapper struct {
	result authenticationcel.CompilationResult
}

func (m *mapper) EvalResponse(ctx context.Context, in traits.Mapper) (*authenticationcel.EvaluationResult, error) {
	return m.eval(ctx, &varNameActivation{name: "response", value: in})
}

func (m *mapper) eval(ctx context.Context, input *varNameActivation) (*authenticationcel.EvaluationResult, error) {
	evaluation := &authenticationcel.EvaluationResult{
		ExpressionAccessor: m.result.ExpressionAccessor,
	}

	evalResult, _, err := m.result.Program.ContextEval(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("expression '%s' resulted in error: %w", m.result.ExpressionAccessor.GetExpression(), err)
	}

	evaluation.EvalResult = evalResult

	return evaluation, nil
}

var _ interpreter.Activation = &varNameActivation{}

type varNameActivation struct {
	name  string
	value traits.Mapper
}

func (v *varNameActivation) ResolveName(name string) (any, bool) {
	if v.name != name {
		return nil, false
	}
	return v.value, true
}

func (v *varNameActivation) Parent() interpreter.Activation { return nil }

func clientAuthenticationForAuthentication(authn apiserver.Authentication) clientAuthentication {
	switch authn.Type {
	case apiserver.AuthenticationTypeRequestProvidedToken:
		return clientAuthentication{
			Type: apiserver.AuthenticationTypeRequestProvidedToken,
		}
	}

	return clientAuthentication{}
}

type externalClaimsResolver struct {
	// TODO implement
	clientAuthentication clientAuthentication
	claims               []externalClaim
	tls                  TLS
}

func (ecr *externalClaimsResolver) expand(ctx context.Context, token string, c claims) error {
	var accessToken string

	if ecr.clientAuthentication.Type == apiserver.AuthenticationTypeRequestProvidedToken {
		accessToken = token
	}

	for _, claim := range ecr.claims {
		// TODO: implement support for evaluating external claim sourcing conditions
		url, err := claim.getURLWithClaims(ctx, c)
		if err != nil {
			return fmt.Errorf("oidc: error during external claims resolution: building external claims URL: %w", err)
		}

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("oidc: error during external claims resolution: building external claims request: %w", err)
		}

		if accessToken != "" {
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
		}

		client := http.DefaultClient

		if ecr.tls.certificateAuthority != "" {
			certPool := x509.NewCertPool()
			certPool.AppendCertsFromPEM([]byte(ecr.tls.certificateAuthority))
			client = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						ClientCAs: certPool,
						// TODO: remove. temporary to resolve:
						// certificate relies on legacy Common Name field, use SANs instead
						InsecureSkipVerify: true,
					},
				},
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("oidc: error during external claims resolution: performing external claims request: %w", err)
		}
		if resp == nil {
			return errors.New("no response?")
		}
		if resp.StatusCode != http.StatusOK {
			responseBody, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("oidc: received non-200 response code when fetching external claims: %d - %s", resp.StatusCode, string(responseBody))
		}

		externalClaims, err := claim.getClaimsFromResponse(ctx, resp)
		for k,v := range externalClaims {
			fmt.Println("key", k, "value", string(v))
		}
		if err != nil {
			return fmt.Errorf("oidc: error during external claims resolution: getting claims from response: %w", err)
		}

		for name, value := range externalClaims {
			c[name] = value
		}
	}

	return nil
}

type clientAuthentication struct {
	Type             apiserver.AuthenticationType
	clientCredential clientCredential
	accessToken      string
}

type clientCredential struct {
	id            string
	secret        string
	tokenEndpoint string
}

type externalClaim struct {
	celMapper externalClaimCELMapper
}

func (ec *externalClaim) getURLWithClaims(ctx context.Context, c claims) (string, error) {
	evaluationResults, err := ec.celMapper.URL.PathExpression.EvalClaimMapping(ctx, newClaimsValue(c))
	if err != nil {
		return "", fmt.Errorf("oidc: error evaluating path expression: %w", err)
	}

	if evaluationResults.EvalResult.Type().TypeName() != cel.ListType(cel.DynType).TypeName() {
		return "", fmt.Errorf("oidc: error evaluating path expression: %w", fmt.Errorf("path expression must return a list, but got %v", evaluationResults.EvalResult.Type()))
	}

	// TODO: optimize
	pathSegmentsVal := evaluationResults.EvalResult.Value()

	refVals, ok := pathSegmentsVal.([]ref.Val)
	if !ok {
		return "", fmt.Errorf("could not convert output type %T to list of values", pathSegmentsVal)
	}

	pathSegments := []string{}

	for _, val := range refVals {
		str, ok := val.Value().(string)
		if !ok {
			return "", fmt.Errorf("could not convert list element type %T to string", val.Value())
		}

		pathSegments = append(pathSegments, str)
	}

	path := ""
	for _, pathSegment := range pathSegments {
		var err error
		path, err = url.JoinPath(path, url.PathEscape(pathSegment))
		if err != nil {
			return "", fmt.Errorf("oidc: error building url path: %w", err)
		}
	}

	urlStr := fmt.Sprintf("%s/%s", ec.celMapper.URL.Base, path)

	return urlStr, nil
}

func (ec *externalClaim) getClaimsFromResponse(ctx context.Context, resp *http.Response) (claims, error) {
	externalClaims := claims{}

	responseBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	input := map[string]any{}
	err = json.Unmarshal(responseBodyBytes, &input)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response body: %w", err)
	}

	for claim, mapper := range ec.celMapper.Mappings {
		evalResult, err := mapper.EvalResponse(ctx, types.NewStringInterfaceMap(types.DefaultTypeAdapter, input))
		if err != nil {
			fmt.Printf("error evaluating external claim mapping %q: %v\n", claim, err)
			return nil, fmt.Errorf("error evaluating external claim mapping %q: %w", claim, err)
		}

		// TODO: The output may not be a string. Just allow any value? Only allow a subset of return types? Actually only allow a single string?
		if evalResult.EvalResult.Type() != cel.StringType {
			return nil, fmt.Errorf("error evaluating external claim mapping %q: %w", claim, errors.New("expected a string return type"))
		}

		externalClaims[claim] = json.RawMessage(fmt.Sprintf("%q", evalResult.EvalResult.Value().(string)))
	}

	return externalClaims, nil
}

type externalClaimCELMapper struct {
	URL        urlCELMapper
	Mappings   map[string]ExternalSourceResponseMapper
	Conditions authenticationcel.ClaimsMapper
}

type urlCELMapper struct {
	Base           string
	PathExpression authenticationcel.ClaimsMapper
}

type TLS struct {
	certificateAuthority string
}

type ExternalSourceResponseMapper interface {
	EvalResponse(context.Context, traits.Mapper) (*authenticationcel.EvaluationResult, error)
}
