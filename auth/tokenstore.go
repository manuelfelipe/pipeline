package auth

import (
	"fmt"
	"sync"
	"time"

	"github.com/banzaicloud/bank-vaults/vault"
	vaultapi "github.com/hashicorp/vault/api"
)

// Verify tokenstores satisfy the correct interface
var _ TokenStore = (*inMemoryTokenStore)(nil)
var _ TokenStore = (*vaultTokenStore)(nil)

// Token represents an access token
type Token struct {
	Name      string
	CreatedAt time.Time
}

// TokenStore is general interface for storing access tokens
type TokenStore interface {
	Store(userID string, tokenID string) error
	Lookup(userID string, tokenID string) (string, error)
	Revoke(userID string, tokenID string) error
	List(userID string) ([]string, error)
}

// In-memory implementation

// NewInMemoryTokenStore is a basic in-memory TokenStore implementation (thread-safe)
func NewInMemoryTokenStore() TokenStore {
	return &inMemoryTokenStore{store: make(map[string]map[string]string)}
}

type inMemoryTokenStore struct {
	sync.RWMutex
	store map[string]map[string]string
}

func (tokenStore *inMemoryTokenStore) Store(userId, token string) error {
	tokenStore.Lock()
	defer tokenStore.Unlock()
	var userTokens map[string]string
	var ok bool
	if userTokens, ok = tokenStore.store[userId]; !ok {
		userTokens = make(map[string]string)
	}
	userTokens[token] = token
	tokenStore.store[userId] = userTokens
	return nil
}

func (tokenStore *inMemoryTokenStore) Lookup(userId, token string) (string, error) {
	tokenStore.RLock()
	defer tokenStore.RUnlock()
	if userTokens, ok := tokenStore.store[userId]; ok {
		token, _ := userTokens[token]
		return token, nil
	}
	return "", nil
}

func (tokenStore *inMemoryTokenStore) Revoke(userId, token string) error {
	tokenStore.Lock()
	defer tokenStore.Unlock()
	if userTokens, ok := tokenStore.store[userId]; ok {
		delete(userTokens, token)
	}
	return nil
}

func (tokenStore *inMemoryTokenStore) List(userId string) ([]string, error) {
	tokenStore.Lock()
	defer tokenStore.Unlock()
	if userTokens, ok := tokenStore.store[userId]; ok {
		tokens := make([]string, len(userTokens))
		i := 0
		for k := range userTokens {
			tokens[i] = k
			i++
		}
		return tokens, nil
	}
	return nil, nil
}

// Vault based implementation

// A TokenStore implementation which stores tokens in Vault
// For local development:
// $ vault server -dev &
// $ export VAULT_ADDR='http://127.0.0.1:8200'
type vaultTokenStore struct {
	client  *vault.Client
	logical *vaultapi.Logical
}

//NewVaultTokenStore creates a new Vault backed token store
func NewVaultTokenStore() TokenStore {
	role := "pipeline"
	client, err := vault.NewClient(role)
	if err != nil {
		panic(err)
	}
	logical := client.Vault().Logical()
	return vaultTokenStore{client: client, logical: logical}
}

func tokenPath(userId, token string) string {
	return fmt.Sprintf("secret/accesstokens/%s/%s", userId, token)
}

func (tokenStore vaultTokenStore) Store(userId, token string) error {
	data := map[string]interface{}{"token": token}
	_, err := tokenStore.logical.Write(tokenPath(userId, token), data)
	return err
}

func (tokenStore vaultTokenStore) Lookup(userId, token string) (string, error) {
	secret, err := tokenStore.logical.Read(tokenPath(userId, token))
	if err != nil {
		return "", err
	}
	return secret.Data["token"].(string), nil
}

func (tokenStore vaultTokenStore) Revoke(userId, token string) error {
	_, err := tokenStore.logical.Delete(tokenPath(userId, token))
	return err
}

func (tokenStore vaultTokenStore) List(userId string) ([]string, error) {
	secret, err := tokenStore.logical.List(fmt.Sprintf("secret/accesstokens/%s", userId))
	if err != nil {
		return nil, err
	}

	keys := secret.Data["keys"].([]interface{})
	tokens := make([]string, len(keys))
	for i, key := range keys {
		tokens[i] = key.(string)
	}
	return tokens, nil
}
