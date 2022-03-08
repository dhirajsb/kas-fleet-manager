/*
 * Connector Service Fleet Manager
 *
 * Connector Service Fleet Manager is a Rest API to manage connectors.
 *
 * API version: 0.1.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package public

// ConnectorClusterState the model 'ConnectorClusterState'
type ConnectorClusterState string

// List of ConnectorClusterState
const (
	CONNECTORCLUSTERSTATE_DISCONNECTED ConnectorClusterState = "disconnected"
	CONNECTORCLUSTERSTATE_READY        ConnectorClusterState = "ready"
	CONNECTORCLUSTERSTATE_DELETING     ConnectorClusterState = "deleting"
)
