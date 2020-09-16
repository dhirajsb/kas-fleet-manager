package services

import (
	"fmt"

	sdkClient "github.com/openshift-online/ocm-sdk-go"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/rs/xid"
	"gitlab.cee.redhat.com/service/managed-services-api/pkg/api"
	strimzi "gitlab.cee.redhat.com/service/managed-services-api/pkg/api/kafka.strimzi.io/v1beta1"
	"gitlab.cee.redhat.com/service/managed-services-api/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//go:generate moq -out syncset_mock.go . SyncsetService
type SyncsetService interface {
	Create(syncsetBuilder *cmv1.SyncsetBuilder, syncsetId, clusterId string) (*cmv1.Syncset, *errors.ServiceError)
}

func NewSyncsetService(ocmClient *sdkClient.Connection) SyncsetService {
	return &syncsetService{
		ocmClient: ocmClient,
	}
}

var _ SyncsetService = &syncsetService{}

type syncsetService struct {
	ocmClient *sdkClient.Connection
}

// Create builds the syncset and syncs it to the desired cluster
func (s syncsetService) Create(syncsetBuilder *cmv1.SyncsetBuilder, syncsetId, clusterId string) (*cmv1.Syncset, *errors.ServiceError) {
	syncsetBuilder.ID(syncsetId)
	syncset, buildErr := syncsetBuilder.Build()
	if buildErr != nil {
		return nil, errors.GeneralError("failed to build syncset: %s", buildErr)
	}

	// create the syncset on the cluster
	clustersResource := s.ocmClient.ClustersMgmt().V1().Clusters()
	response, syncsetErr := clustersResource.Cluster(clusterId).
		ExternalConfiguration().
		Syncsets().
		Add().
		Body(syncset).
		Send()
	if syncsetErr != nil {
		fmt.Println(syncsetErr)
		return nil, errors.GeneralError(fmt.Sprintf("failed to create syncset: %s for cluster id: %s", syncset.ID(), clusterId), syncsetErr)
	}
	return response.Body(), nil
}

// syncset builder for a kafka/strimzi custom resource
func newKafkaSyncsetBuilder(kafkaRequest *api.KafkaRequest) (*cmv1.SyncsetBuilder, string, *errors.ServiceError) {
	kafkaName := fmt.Sprintf("%s-%s", kafkaRequest.Name, xid.New().String())

	// build array of objects to be created by the syncset
	resources := []interface{}{
		&strimzi.Kafka{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "kafka.strimzi.io/v1beta1",
				Kind:       "Kafka",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      kafkaRequest.Name,
				Namespace: kafkaName,
			},
			Spec: strimzi.KafkaSpec{
				Kafka: strimzi.KafkaClusterSpec{
					Replicas: 3,
					Storage: strimzi.Storage{
						Type: strimzi.Ephemeral,
					},
					Listeners: strimzi.KafkaListeners{
						Plain: &strimzi.KafkaListenerPlain{},
						TLS:   &strimzi.KafkaListenerTLS{},
					},
				},
				Zookeeper: strimzi.ZookeeperClusterSpec{
					Replicas: 3,
					Storage: strimzi.Storage{
						Type: strimzi.Ephemeral,
					},
				},
				EntityOperator: strimzi.EntityOperatorSpec{
					TopicOperator: strimzi.EntityTopicOperatorSpec{},
					UserOperator:  strimzi.EntityUserOperatorSpec{},
				},
			},
		},
	}

	syncsetBuilder := cmv1.NewSyncset()
	syncsetBuilder = syncsetBuilder.Resources(resources...)

	// build the syncset - "ext-" prefix is required
	return syncsetBuilder, fmt.Sprintf("ext-%s", kafkaName), nil
}
