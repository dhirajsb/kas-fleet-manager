package authorization

import (
	"context"
	"github.com/bf2fc6cc711aee1a0c2a/kas-fleet-manager/pkg/auth"
	"github.com/bf2fc6cc711aee1a0c2a/kas-fleet-manager/pkg/db"
	"github.com/bf2fc6cc711aee1a0c2a/kas-fleet-manager/pkg/errors"
	"github.com/patrickmn/go-cache"
	"time"
	"unsafe"
)

type UserAuthorizationService interface {
	GetUserInfo(ctx context.Context) (*UserInfo, error)
	DeleteCachedUserInfo(userId string)
}

type userAuthorizationService struct {
	factory *db.ConnectionFactory
	cache   *cache.Cache // TODO replace with something more sophisticated
}

var _ UserAuthorizationService = &userAuthorizationService{}

func NewUserAuthorizationService(factory *db.ConnectionFactory) *userAuthorizationService {
	return &userAuthorizationService{
		factory: factory,
		cache:   cache.New(5*time.Minute, 10*time.Minute),
	}
}

type EmptyValue struct{}

type StringSet map[string]EmptyValue
var EMPTY struct{}

func (set StringSet) Contains(key string) bool {
	_, ok := set[key]
	return ok
}

type UserInfo struct {
	UserID              string
	OrganisationID      string
	IsOrganisationAdmin bool
	OwnerClusters       StringSet
	OrgClusters         StringSet
	OwnerNamespaces     StringSet
	UserNamespaces      StringSet
	OrgNamespaces       StringSet
}

type clusterInfo struct {
	ID             string
	Owner          string
	OrganisationId string
}

type namespaceInfo struct {
	ID                   string
	Owner                string
	TenantUserId         *string
	TenantOrganisationId *string
}

func (service *userAuthorizationService) GetUserInfo(ctx context.Context) (*UserInfo, error) {
	claims, err := auth.GetClaimsFromContext(ctx)
	if err != nil {
		return nil, errors.NewWithCause(errors.ErrorUnauthenticated, err, "user not authenticated")
	}
	userID := auth.GetUsernameFromClaims(claims)
	orgID := auth.GetOrgIdFromClaims(claims)

	// fetch from cache first
	if entry, ok := service.cache.Get(userID); ok {
		return entry.(*UserInfo), nil
	}

	userInfo := UserInfo{
		UserID:              userID,
		OrganisationID:      orgID,
		IsOrganisationAdmin: auth.GetIsOrgAdminFromClaims(claims),
		OwnerClusters:       make(StringSet),
		OrgClusters:         make(StringSet),
		OwnerNamespaces:     make(StringSet),
		UserNamespaces:      make(StringSet),
		OrgNamespaces:       make(StringSet),
	}

	var clusters []clusterInfo
	dbConn := service.factory.New()
	if err := dbConn.Table("connector_clusters").
		Select("id, owner, organisation_id").
		Where("deleted_at IS NULL AND (owner = ? OR organisation_id = ?)", userID, orgID).
		Order("id ASC").
		Find(&clusters).Error; err != nil {
		return nil, errors.Unauthorized("error retrieving clusters for user %s: %s", userID, err)
	}
	for _, cluster := range clusters {
		if cluster.Owner == userID {
			userInfo.OwnerClusters[cluster.ID] = EMPTY
		} else {
			userInfo.OrgClusters[cluster.ID] = EMPTY
		}
	}
	var namespaces []namespaceInfo
	dbConn = service.factory.New()
	if err := dbConn.Table("connector_namespaces").
		Select("id, owner, tenant_user_id, tenant_organisation_id").
		Where("deleted_at IS NULL AND (owner = ? OR tenant_user_id = ? OR tenant_organisation_id = ?)", userID, userID, orgID).
		Order("id ASC").
		Find(&namespaces).Error; err != nil {
		return nil, errors.Unauthorized("error retrieving namespaces for user %s: %s", userID, err)
	}
	for _, namespace := range namespaces {
		if namespace.Owner == userID {
			userInfo.OwnerNamespaces[namespace.ID] = EMPTY
		} else if namespace.TenantUserId != nil && *namespace.TenantUserId == userID {
			userInfo.UserNamespaces[namespace.ID] = EMPTY
		} else {
			userInfo.OrgNamespaces[namespace.ID] = EMPTY
		}
	}

	size := unsafe.Sizeof(userInfo)
	service.cache.Set(userID, &userInfo, time.Duration(0 * size))
	return &userInfo, nil
}

func (service *userAuthorizationService) DeleteCachedUserInfo(userId string) {
	service.cache.Delete(userId)
}
