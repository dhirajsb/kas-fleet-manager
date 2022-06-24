/*
 * Kafka Service Fleet Manager Admin APIs
 *
 * The admin APIs for the fleet manager of Kafka service
 *
 * API version: 0.1.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package private

import (
	"time"
)

// Kafka struct for Kafka
type Kafka struct {
	Id   string `json:"id"`
	Kind string `json:"kind"`
	Href string `json:"href"`
	// Values: [accepted, preparing, provisioning, ready, failed, deprovision, deleting]
	Status string `json:"status,omitempty"`
	// Name of Cloud used to deploy. For example AWS
	CloudProvider string `json:"cloud_provider,omitempty"`
	MultiAz       bool   `json:"multi_az"`
	// Values will be regions of specific cloud provider. For example: us-east-1 for AWS
	Region                 string    `json:"region,omitempty"`
	Owner                  string    `json:"owner,omitempty"`
	Name                   string    `json:"name,omitempty"`
	BootstrapServerHost    string    `json:"bootstrap_server_host,omitempty"`
	CreatedAt              time.Time `json:"created_at,omitempty"`
	UpdatedAt              time.Time `json:"updated_at,omitempty"`
	FailedReason           string    `json:"failed_reason,omitempty"`
	ActualKafkaVersion     string    `json:"actual_kafka_version,omitempty"`
	ActualStrimziVersion   string    `json:"actual_strimzi_version,omitempty"`
	DesiredKafkaVersion    string    `json:"desired_kafka_version,omitempty"`
	DesiredStrimziVersion  string    `json:"desired_strimzi_version,omitempty"`
	DesiredKafkaIbpVersion string    `json:"desired_kafka_ibp_version,omitempty"`
	ActualKafkaIbpVersion  string    `json:"actual_kafka_ibp_version,omitempty"`
	KafkaUpgrading         bool      `json:"kafka_upgrading"`
	StrimziUpgrading       bool      `json:"strimzi_upgrading"`
	KafkaIbpUpgrading      bool      `json:"kafka_ibp_upgrading"`
	// Maximum data storage available to this Kafka. This is now deprecated, please use max_data_retention_size instead.
	// Deprecated
	DeprecatedKafkaStorageSize string                           `json:"kafka_storage_size,omitempty"`
	OrganisationId             string                           `json:"organisation_id,omitempty"`
	SubscriptionId             string                           `json:"subscription_id,omitempty"`
	OwnerAccountId             string                           `json:"owner_account_id,omitempty"`
	AccountNumber              string                           `json:"account_number,omitempty"`
	InstanceType               string                           `json:"instance_type,omitempty"`
	QuotaType                  string                           `json:"quota_type,omitempty"`
	Routes                     []KafkaAllOfRoutes               `json:"routes,omitempty"`
	RoutesCreated              bool                             `json:"routes_created,omitempty"`
	ClusterId                  string                           `json:"cluster_id,omitempty"`
	Namespace                  string                           `json:"namespace,omitempty"`
	SizeId                     string                           `json:"size_id,omitempty"`
	MaxDataRetentionSize       SupportedKafkaSizeBytesValueItem `json:"max_data_retention_size,omitempty"`
}
