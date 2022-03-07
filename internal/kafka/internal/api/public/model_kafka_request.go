/*
 * Kafka Service Fleet Manager
 *
 * Kafka Service Fleet Manager is a Rest API to manage Kafka instances.
 *
 * API version: 1.3.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package public

import (
	"time"
)

// KafkaRequest struct for KafkaRequest
type KafkaRequest struct {
	Id   string `json:"id,omitempty"`
	Kind string `json:"kind,omitempty"`
	Href string `json:"href,omitempty"`
	// Values: [accepted, preparing, provisioning, ready, failed, deprovision, deleting]
	Status string `json:"status,omitempty"`
	// Name of Cloud used to deploy. For example AWS
	CloudProvider string `json:"cloud_provider,omitempty"`
	MultiAz       bool   `json:"multi_az"`
	// Values will be regions of specific cloud provider. For example: us-east-1 for AWS
	Region                  string    `json:"region,omitempty"`
	Owner                   string    `json:"owner,omitempty"`
	Name                    string    `json:"name,omitempty"`
	BootstrapServerHost     string    `json:"bootstrap_server_host,omitempty"`
	CreatedAt               time.Time `json:"created_at,omitempty"`
	UpdatedAt               time.Time `json:"updated_at,omitempty"`
	FailedReason            string    `json:"failed_reason,omitempty"`
	Version                 string    `json:"version,omitempty"`
	InstanceType            string    `json:"instance_type,omitempty"`
	ReauthenticationEnabled bool      `json:"reauthentication_enabled"`
	KafkaStorageSize        string    `json:"kafka_storage_size,omitempty"`
	BrowserUrl              string    `json:"browser_url,omitempty"`
}
