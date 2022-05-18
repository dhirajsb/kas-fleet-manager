/*
 * Kafka Service Fleet Manager
 *
 * Kafka Service Fleet Manager APIs that are used by internal services e.g kas-fleetshard operators.
 *
 * API version: 1.5.1
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package private

// ManagedKafka struct for ManagedKafka
type ManagedKafka struct {
	Id       string                    `json:"id,omitempty"`
	Kind     string                    `json:"kind,omitempty"`
	Metadata ManagedKafkaAllOfMetadata `json:"metadata,omitempty"`
	Spec     ManagedKafkaAllOfSpec     `json:"spec,omitempty"`
}
