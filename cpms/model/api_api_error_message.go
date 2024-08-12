// Code generated by go-swagger; DO NOT EDIT.

package model

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// APIAPIErrorMessage api api error message
//
// swagger:model api.apiErrorMessage
type APIAPIErrorMessage struct {

	// message
	Message string `json:"message,omitempty"`
}

// Validate validates this api api error message
func (m *APIAPIErrorMessage) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this api api error message based on context it is used
func (m *APIAPIErrorMessage) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *APIAPIErrorMessage) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APIAPIErrorMessage) UnmarshalBinary(b []byte) error {
	var res APIAPIErrorMessage
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
