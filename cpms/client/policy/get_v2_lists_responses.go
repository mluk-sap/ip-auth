// Code generated by go-swagger; DO NOT EDIT.

package policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/kyma-project/ip-auth/cpms/model"
)

// GetV2ListsReader is a Reader for the GetV2Lists structure.
type GetV2ListsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetV2ListsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetV2ListsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetV2ListsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetV2ListsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetV2ListsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetV2ListsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 503:
		result := NewGetV2ListsServiceUnavailable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /v2/lists] GetV2Lists", response, response.Code())
	}
}

// NewGetV2ListsOK creates a GetV2ListsOK with default headers values
func NewGetV2ListsOK() *GetV2ListsOK {
	return &GetV2ListsOK{}
}

/*
GetV2ListsOK describes a response with status code 200, with default header values.

OK
*/
type GetV2ListsOK struct {
	Payload []*model.PolicyActivePolicy
}

// IsSuccess returns true when this get v2 lists o k response has a 2xx status code
func (o *GetV2ListsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get v2 lists o k response has a 3xx status code
func (o *GetV2ListsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get v2 lists o k response has a 4xx status code
func (o *GetV2ListsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get v2 lists o k response has a 5xx status code
func (o *GetV2ListsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get v2 lists o k response a status code equal to that given
func (o *GetV2ListsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get v2 lists o k response
func (o *GetV2ListsOK) Code() int {
	return 200
}

func (o *GetV2ListsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v2/lists][%d] getV2ListsOK %s", 200, payload)
}

func (o *GetV2ListsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v2/lists][%d] getV2ListsOK %s", 200, payload)
}

func (o *GetV2ListsOK) GetPayload() []*model.PolicyActivePolicy {
	return o.Payload
}

func (o *GetV2ListsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetV2ListsBadRequest creates a GetV2ListsBadRequest with default headers values
func NewGetV2ListsBadRequest() *GetV2ListsBadRequest {
	return &GetV2ListsBadRequest{}
}

/*
GetV2ListsBadRequest describes a response with status code 400, with default header values.

Please provide policyIDs in the following format: `policyIDs='<projectID1>/<policyID1>,<projectID2>/<policyID2>'`
*/
type GetV2ListsBadRequest struct {
	Payload *model.APIErrorResponse
}

// IsSuccess returns true when this get v2 lists bad request response has a 2xx status code
func (o *GetV2ListsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get v2 lists bad request response has a 3xx status code
func (o *GetV2ListsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get v2 lists bad request response has a 4xx status code
func (o *GetV2ListsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get v2 lists bad request response has a 5xx status code
func (o *GetV2ListsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get v2 lists bad request response a status code equal to that given
func (o *GetV2ListsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get v2 lists bad request response
func (o *GetV2ListsBadRequest) Code() int {
	return 400
}

func (o *GetV2ListsBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v2/lists][%d] getV2ListsBadRequest %s", 400, payload)
}

func (o *GetV2ListsBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v2/lists][%d] getV2ListsBadRequest %s", 400, payload)
}

func (o *GetV2ListsBadRequest) GetPayload() *model.APIErrorResponse {
	return o.Payload
}

func (o *GetV2ListsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.APIErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetV2ListsForbidden creates a GetV2ListsForbidden with default headers values
func NewGetV2ListsForbidden() *GetV2ListsForbidden {
	return &GetV2ListsForbidden{}
}

/*
GetV2ListsForbidden describes a response with status code 403, with default header values.

Access denied
*/
type GetV2ListsForbidden struct {
}

// IsSuccess returns true when this get v2 lists forbidden response has a 2xx status code
func (o *GetV2ListsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get v2 lists forbidden response has a 3xx status code
func (o *GetV2ListsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get v2 lists forbidden response has a 4xx status code
func (o *GetV2ListsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get v2 lists forbidden response has a 5xx status code
func (o *GetV2ListsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get v2 lists forbidden response a status code equal to that given
func (o *GetV2ListsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get v2 lists forbidden response
func (o *GetV2ListsForbidden) Code() int {
	return 403
}

func (o *GetV2ListsForbidden) Error() string {
	return fmt.Sprintf("[GET /v2/lists][%d] getV2ListsForbidden", 403)
}

func (o *GetV2ListsForbidden) String() string {
	return fmt.Sprintf("[GET /v2/lists][%d] getV2ListsForbidden", 403)
}

func (o *GetV2ListsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetV2ListsNotFound creates a GetV2ListsNotFound with default headers values
func NewGetV2ListsNotFound() *GetV2ListsNotFound {
	return &GetV2ListsNotFound{}
}

/*
GetV2ListsNotFound describes a response with status code 404, with default header values.

Requested Policy not found
*/
type GetV2ListsNotFound struct {
	Payload *model.APIErrorResponse
}

// IsSuccess returns true when this get v2 lists not found response has a 2xx status code
func (o *GetV2ListsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get v2 lists not found response has a 3xx status code
func (o *GetV2ListsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get v2 lists not found response has a 4xx status code
func (o *GetV2ListsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get v2 lists not found response has a 5xx status code
func (o *GetV2ListsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get v2 lists not found response a status code equal to that given
func (o *GetV2ListsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get v2 lists not found response
func (o *GetV2ListsNotFound) Code() int {
	return 404
}

func (o *GetV2ListsNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v2/lists][%d] getV2ListsNotFound %s", 404, payload)
}

func (o *GetV2ListsNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v2/lists][%d] getV2ListsNotFound %s", 404, payload)
}

func (o *GetV2ListsNotFound) GetPayload() *model.APIErrorResponse {
	return o.Payload
}

func (o *GetV2ListsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.APIErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetV2ListsInternalServerError creates a GetV2ListsInternalServerError with default headers values
func NewGetV2ListsInternalServerError() *GetV2ListsInternalServerError {
	return &GetV2ListsInternalServerError{}
}

/*
GetV2ListsInternalServerError describes a response with status code 500, with default header values.

Internal server error
*/
type GetV2ListsInternalServerError struct {
	Payload *model.APIErrorResponse
}

// IsSuccess returns true when this get v2 lists internal server error response has a 2xx status code
func (o *GetV2ListsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get v2 lists internal server error response has a 3xx status code
func (o *GetV2ListsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get v2 lists internal server error response has a 4xx status code
func (o *GetV2ListsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get v2 lists internal server error response has a 5xx status code
func (o *GetV2ListsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get v2 lists internal server error response a status code equal to that given
func (o *GetV2ListsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get v2 lists internal server error response
func (o *GetV2ListsInternalServerError) Code() int {
	return 500
}

func (o *GetV2ListsInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v2/lists][%d] getV2ListsInternalServerError %s", 500, payload)
}

func (o *GetV2ListsInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v2/lists][%d] getV2ListsInternalServerError %s", 500, payload)
}

func (o *GetV2ListsInternalServerError) GetPayload() *model.APIErrorResponse {
	return o.Payload
}

func (o *GetV2ListsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.APIErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetV2ListsServiceUnavailable creates a GetV2ListsServiceUnavailable with default headers values
func NewGetV2ListsServiceUnavailable() *GetV2ListsServiceUnavailable {
	return &GetV2ListsServiceUnavailable{}
}

/*
GetV2ListsServiceUnavailable describes a response with status code 503, with default header values.

Service unavailable
*/
type GetV2ListsServiceUnavailable struct {
}

// IsSuccess returns true when this get v2 lists service unavailable response has a 2xx status code
func (o *GetV2ListsServiceUnavailable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get v2 lists service unavailable response has a 3xx status code
func (o *GetV2ListsServiceUnavailable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get v2 lists service unavailable response has a 4xx status code
func (o *GetV2ListsServiceUnavailable) IsClientError() bool {
	return false
}

// IsServerError returns true when this get v2 lists service unavailable response has a 5xx status code
func (o *GetV2ListsServiceUnavailable) IsServerError() bool {
	return true
}

// IsCode returns true when this get v2 lists service unavailable response a status code equal to that given
func (o *GetV2ListsServiceUnavailable) IsCode(code int) bool {
	return code == 503
}

// Code gets the status code for the get v2 lists service unavailable response
func (o *GetV2ListsServiceUnavailable) Code() int {
	return 503
}

func (o *GetV2ListsServiceUnavailable) Error() string {
	return fmt.Sprintf("[GET /v2/lists][%d] getV2ListsServiceUnavailable", 503)
}

func (o *GetV2ListsServiceUnavailable) String() string {
	return fmt.Sprintf("[GET /v2/lists][%d] getV2ListsServiceUnavailable", 503)
}

func (o *GetV2ListsServiceUnavailable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}