package client

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/telesma-app/ctap/diagnostic"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

func (cl *Client) exchange(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	if cl.diagnosticSink == nil {
		return cl.transport.CBOR(ctx, data)
	}

	started := time.Now()
	response, err := cl.transport.CBOR(ctx, data)
	duration := time.Since(started)
	cl.emitDiagnostic(ctx, started, duration, data, response, err)

	return response, err
}

func (cl *Client) emitDiagnostic(
	ctx context.Context,
	started time.Time,
	duration time.Duration,
	data []byte,
	response ctaptransport.CBORResponse,
	err error,
) {
	command := protocol.Command(data[0])
	requestBody := data[1:]
	requestSchema, responseSchema := exchangeSchemas(command)
	request, subCommand := renderDiagnostic(cl.decMode, cl.encMode, requestBody, requestSchema)
	responseDiagnostic, _ := renderDiagnostic(cl.decMode, cl.encMode, response.Data, responseSchema)

	event := diagnostic.Exchange{
		StartedAt:  started.UTC(),
		Duration:   duration,
		Command:    command,
		SubCommand: subCommand,
		Request:    request,
		Response:   responseDiagnostic,
		Err:        err,
	}
	if status, ok := exchangeStatus(response, err); ok {
		event.Status = &status
	}

	cl.diagnosticSink(ctx, event)
}

type diagnosticExchangeSchema struct {
	requestType             reflect.Type
	responseType            reflect.Type
	requestSubCommandParams map[uint64]reflect.Type
	responseMapValueTypes   map[diagnosticMapValueKey]reflect.Type
}

var unsignedExtensionOutputLargeBlobKey = diagnosticMapValueKey{
	path: "UnsignedExtensionOutputs",
	key:  string(extension.ExtensionIdentifierLargeBlob),
}

var unsignedExtensionOutputPreviewSignKey = diagnosticMapValueKey{
	path: "UnsignedExtensionOutputs",
	key:  string(extension.ExtensionIdentifierPreviewSign),
}

var getAssertionDiagnosticMapValueTypes = map[diagnosticMapValueKey]reflect.Type{
	unsignedExtensionOutputLargeBlobKey: reflect.TypeFor[protocol.GetLargeBlobOutput](),
}

var diagnosticExchangeSchemas = map[protocol.Command]diagnosticExchangeSchema{
	protocol.AuthenticatorMakeCredential: {
		requestType:  reflect.TypeFor[protocol.AuthenticatorMakeCredentialRequest](),
		responseType: reflect.TypeFor[protocol.AuthenticatorMakeCredentialResponse](),
		responseMapValueTypes: map[diagnosticMapValueKey]reflect.Type{
			unsignedExtensionOutputLargeBlobKey:   reflect.TypeFor[protocol.CreateLargeBlobOutput](),
			unsignedExtensionOutputPreviewSignKey: reflect.TypeFor[protocol.PreviewSignUnsignedOutput](),
		},
	},
	protocol.AuthenticatorGetAssertion: {
		requestType:           reflect.TypeFor[protocol.AuthenticatorGetAssertionRequest](),
		responseType:          reflect.TypeFor[protocol.AuthenticatorGetAssertionResponse](),
		responseMapValueTypes: getAssertionDiagnosticMapValueTypes,
	},
	protocol.AuthenticatorGetNextAssertion: {
		responseType:          reflect.TypeFor[protocol.AuthenticatorGetAssertionResponse](),
		responseMapValueTypes: getAssertionDiagnosticMapValueTypes,
	},
	protocol.AuthenticatorGetInfo: {
		responseType: reflect.TypeFor[protocol.AuthenticatorGetInfoResponse](),
	},
	protocol.AuthenticatorClientPIN: {
		requestType:  reflect.TypeFor[protocol.AuthenticatorClientPINRequest](),
		responseType: reflect.TypeFor[protocol.AuthenticatorClientPINResponse](),
	},
	protocol.AuthenticatorBioEnrollment: {
		requestType:  reflect.TypeFor[protocol.AuthenticatorBioEnrollmentRequest](),
		responseType: reflect.TypeFor[protocol.AuthenticatorBioEnrollmentResponse](),
	},
	protocol.PrototypeAuthenticatorBioEnrollment: {
		requestType:  reflect.TypeFor[protocol.AuthenticatorBioEnrollmentRequest](),
		responseType: reflect.TypeFor[protocol.AuthenticatorBioEnrollmentResponse](),
	},
	protocol.AuthenticatorCredentialManagement: {
		requestType:  reflect.TypeFor[protocol.AuthenticatorCredentialManagementRequest](),
		responseType: reflect.TypeFor[protocol.AuthenticatorCredentialManagementResponse](),
	},
	protocol.PrototypeAuthenticatorCredentialManagement: {
		requestType:  reflect.TypeFor[protocol.AuthenticatorCredentialManagementRequest](),
		responseType: reflect.TypeFor[protocol.AuthenticatorCredentialManagementResponse](),
	},
	protocol.AuthenticatorLargeBlobs: {
		requestType:  reflect.TypeFor[protocol.AuthenticatorLargeBlobsRequest](),
		responseType: reflect.TypeFor[protocol.AuthenticatorLargeBlobsResponse](),
	},
	protocol.AuthenticatorConfig: {
		requestType: reflect.TypeFor[protocol.AuthenticatorConfigRequest](),
		requestSubCommandParams: map[uint64]reflect.Type{
			uint64(protocol.ConfigSubCommandSetMinPINLength): reflect.TypeFor[protocol.SetMinPINLengthConfigSubCommandParams](),
		},
	},
}

func exchangeSchemas(command protocol.Command) (diagnosticMessageSchema, diagnosticMessageSchema) {
	schema := diagnosticExchangeSchemas[command]
	request := diagnosticMessageSchema{
		typeInfo:         schema.requestType,
		subCommandParams: schema.requestSubCommandParams,
	}
	response := diagnosticMessageSchema{
		typeInfo:      schema.responseType,
		mapValueTypes: schema.responseMapValueTypes,
	}

	return request, response
}

func exchangeStatus(
	response ctaptransport.CBORResponse,
	err error,
) (ctaptransport.StatusCode, bool) {
	if ctapErr, ok := errors.AsType[*ctaptransport.CTAPError](err); ok {
		return ctapErr.StatusCode, true
	}

	if err == nil {
		return response.StatusCode, true
	}

	return 0, false
}
