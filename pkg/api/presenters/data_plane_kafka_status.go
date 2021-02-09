package presenters

import (
	"gitlab.cee.redhat.com/service/managed-services-api/pkg/api"
	"gitlab.cee.redhat.com/service/managed-services-api/pkg/api/openapi"
)

func ConvertDataPlaneKafkaStatus(status map[string]openapi.DataPlaneKafkaStatus) []*api.DataPlaneKafkaStatus {
	var r []*api.DataPlaneKafkaStatus
	for k, v := range status {
		var c []api.DataPlaneKafkaStatusCondition
		for _, s := range v.Conditions {
			c = append(c, api.DataPlaneKafkaStatusCondition{
				Type:    s.Type,
				Reason:  s.Reason,
				Status:  s.Status,
				Message: s.Message,
			})
		}
		r = append(r, &api.DataPlaneKafkaStatus{
			KafkaClusterId: k,
			Conditions:     c,
		})
	}

	return r
}
