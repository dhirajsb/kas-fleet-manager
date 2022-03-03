/*
 * Connector Service Fleet Manager
 *
 * Connector Service Fleet Manager is a Rest API to manage connectors.
 *
 * API version: 0.1.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package public

// ConnectorNamespacePatchRequest A connector namespace patch request
type ConnectorNamespacePatchRequest struct {
	Name        string                                     `json:"name,omitempty"`
	Annotations []ConnectorNamespaceRequestMetaAnnotations `json:"annotations,omitempty"`
}
