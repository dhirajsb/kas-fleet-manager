package quota

import (
	"fmt"
	"github.com/bf2fc6cc711aee1a0c2a/kas-fleet-manager/pkg/quota_management"

	"github.com/bf2fc6cc711aee1a0c2a/kas-fleet-manager/internal/kafka/internal/api/dbapi"
	"github.com/bf2fc6cc711aee1a0c2a/kas-fleet-manager/internal/kafka/internal/kafkas/types"
	"github.com/bf2fc6cc711aee1a0c2a/kas-fleet-manager/pkg/db"
	"github.com/bf2fc6cc711aee1a0c2a/kas-fleet-manager/pkg/errors"
)

type QuotaManagementListService struct {
	connectionFactory   *db.ConnectionFactory
	quotaManagementList *quota_management.QuotaManagementListConfig
}

func (q QuotaManagementListService) CheckIfQuotaIsDefinedForInstanceType(kafka *dbapi.KafkaRequest, instanceType types.KafkaInstanceType) (bool, *errors.ServiceError) {
	username := kafka.Owner
	orgId := kafka.OrganisationId
	org, orgFound := q.quotaManagementList.QuotaList.Organisations.GetById(orgId)
	userIsRegistered := false
	if orgFound && org.IsUserRegistered(username) {
		userIsRegistered = true
	} else {
		_, userFound := q.quotaManagementList.QuotaList.ServiceAccounts.GetByUsername(username)
		userIsRegistered = userFound
	}

	// allow user defined in quota list to create standard instances
	if userIsRegistered && instanceType == types.STANDARD {
		return true, nil
	} else if !userIsRegistered && instanceType == types.EVAL { // allow user who are not in quota list to create eval instances
		return true, nil
	}

	return false, nil
}

func (q QuotaManagementListService) ReserveQuota(kafka *dbapi.KafkaRequest, instanceType types.KafkaInstanceType) (string, *errors.ServiceError) {
	if !q.quotaManagementList.EnableInstanceLimitControl {
		return "", nil
	}

	username := kafka.Owner
	orgId := kafka.OrganisationId
	var quotaManagementListItem quota_management.QuotaManagementListItem
	message := fmt.Sprintf("User '%s' has reached a maximum number of %d allowed instances.", username, quota_management.GetDefaultMaxAllowedInstances())
	org, orgFound := q.quotaManagementList.QuotaList.Organisations.GetById(orgId)
	filterByOrd := false
	if orgFound && org.IsUserRegistered(username) {
		quotaManagementListItem = org
		message = fmt.Sprintf("Organization '%s' has reached a maximum number of %d allowed instances.", orgId, org.GetMaxAllowedInstances())
		filterByOrd = true
	} else {
		user, userFound := q.quotaManagementList.QuotaList.ServiceAccounts.GetByUsername(username)
		if userFound {
			quotaManagementListItem = user
			message = fmt.Sprintf("User '%s' has reached a maximum number of %d allowed instances.", username, user.GetMaxAllowedInstances())
		}
	}

	var count int64
	dbConn := q.connectionFactory.New().
		Model(&dbapi.KafkaRequest{}).
		Where("instance_type = ?", instanceType.String())

	if instanceType == types.STANDARD && filterByOrd {
		dbConn = dbConn.Where("organisation_id = ?", orgId)
	} else {
		dbConn = dbConn.Where("owner = ?", username)
	}

	if err := dbConn.Count(&count).Error; err != nil {
		return "", errors.GeneralError("count failed from database")
	}

	totalInstanceCount := int(count)
	if quotaManagementListItem != nil && instanceType == types.STANDARD {
		if quotaManagementListItem.IsInstanceCountWithinLimit(totalInstanceCount) {
			return "", nil
		} else {
			return "", errors.MaximumAllowedInstanceReached(message)
		}
	}

	if instanceType == types.EVAL && quotaManagementListItem == nil {
		if totalInstanceCount >= quota_management.GetDefaultMaxAllowedInstances() {
			return "", errors.MaximumAllowedInstanceReached(message)
		}
		return "", nil
	}

	return "", errors.InsufficientQuotaError("Insufficient Quota")
}

func (q QuotaManagementListService) DeleteQuota(SubscriptionId string) *errors.ServiceError {
	return nil // NOOP
}
