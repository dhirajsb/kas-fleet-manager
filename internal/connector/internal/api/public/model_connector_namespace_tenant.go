/*
 * Connector Service Fleet Manager
 *
 * Connector Service Fleet Manager is a Rest API to manage connectors.
 *
 * API version: 0.1.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package public

// ConnectorNamespaceTenant struct for ConnectorNamespaceTenant
type ConnectorNamespaceTenant struct {
	Kind           string `json:"kind"`
	UserId         string `json:"user_id,omitempty"`
	OrganisationId string `json:"organisation_id,omitempty"`
}
