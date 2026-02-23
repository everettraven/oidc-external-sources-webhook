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
	authenticationcel "github.com/everettraven/oidc-external-sources-webhook/pkg/internal/thirdparty/kubernetes/apiserver/pkg/authentication/cel"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/interpreter"
)

type ExternalClaimsCompatibleCompiler interface {
	CompileExternalSourceExpression(expressionAccessor authenticationcel.ExpressionAccessor) (authenticationcel.CompilationResult, error)
}

func NewExternalClaimsResolver(externalClaimSource apiserver.ExternalClaimsSource, compiler authenticationcel.Compiler) (*externalClaimsResolver, error) {
	out := &externalClaimsResolver{}

	out.clientAuthentication = clientAuthenticationForAuthentication(externalClaimSource.Authentication)

	out.tls = TLS{
		certificateAuthority: externalClaimSource.TLS.CA,
	}

	for _, source := range externalClaimSource.Sources {
		pathExpressionCompiled, err := compiler.CompileClaimsExpression(&authenticationcel.ExternalSourceURLExpression{
			Hostname:       source.URL.Base,
			PathExpression: source.URL.PathExpression,
		})
		if err != nil {
			return nil, fmt.Errorf("compiling path expression %q: %w", source.URL.PathExpression, err)
		}

		sourceCompilationResults := []authenticationcel.CompilationResult{}
		for _, mapping := range source.Mappings {
			mappingExpressionCompiled, err := compiler.CompileExternalSourceExpression(&authenticationcel.ExternalSourceMappingExpression{
				Claim:      mapping.Name,
				Expression: mapping.Expression,
			})
			if err != nil {
				return nil, fmt.Errorf("compiling mapping expression %q (%q): %w", mapping.Expression, mapping.Name, err)
			}

			sourceCompilationResults = append(sourceCompilationResults, mappingExpressionCompiled)
		}

		ec := externalClaim{
			celMapper: authenticationcel.ExternalSourceCELMapper{
				URL: authenticationcel.NewClaimsMapper([]authenticationcel.CompilationResult{pathExpressionCompiled}),
				// TODO: Conditions
				Sources: authenticationcel.NewExternalSourcesMapper(sourceCompilationResults),
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
		for k, v := range externalClaims {
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
	celMapper authenticationcel.ExternalSourceCELMapper
}

func (ec *externalClaim) getURLWithClaims(ctx context.Context, c claims) (string, error) {
	evaluationResults, err := ec.celMapper.URL.EvalClaimMapping(ctx, newClaimsValue(c))
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

	urlExpressionAccessor, ok := evaluationResults.ExpressionAccessor.(*authenticationcel.ExternalSourceURLExpression)
	if !ok {
		return "", fmt.Errorf("oidc: error getting url hostname: invalid type conversion, expected ExternalSourceURLExpression")
	}

	urlStr := fmt.Sprintf("https://%s/%s", urlExpressionAccessor.Hostname, path)

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

	evalResults, err := ec.celMapper.Sources.EvalExternalSources(ctx, types.NewStringInterfaceMap(types.DefaultTypeAdapter, input))
	if err != nil {
		return nil, fmt.Errorf("evaluating external source mappings: %w", err)
	}

	for _, result := range evalResults {
		sourceMappingExpressionAccessor, ok := result.ExpressionAccessor.(*authenticationcel.ExternalSourceMappingExpression)
		if !ok {
			return nil, fmt.Errorf("invalid type conversion, expected ExternalSourceMappingExpression")
		}

		// TODO: The output may not be a string. Just allow any value? Only allow a subset of return types? Actually only allow a single string?
		if result.EvalResult.Type() != cel.StringType {
			return nil, fmt.Errorf("error evaluating external claim mapping %q: %w", sourceMappingExpressionAccessor.Claim, errors.New("expected a string return type"))
		}

		externalClaims[sourceMappingExpressionAccessor.Claim] = json.RawMessage(fmt.Sprintf("%q", result.EvalResult.Value().(string)))
	}

	return externalClaims, nil
}

type TLS struct {
	certificateAuthority string
}
