package data

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/tetcd"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/utils"
	"github.com/go-playground/validator/v10"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/clientv3util"
)

func (d *database) generateWebhookSecret(id, plainTextCredentials string) (string, error) {

	res, err := pbkdf2.Key(sha256.New, plainTextCredentials, []byte(id), 10, 32)
	if err != nil {
		return "", fmt.Errorf("unable to determine hash: %w", err)
	}

	return hex.EncodeToString(res), nil
}

type WebhookCreateRequestDTO struct {
	config.Webhook
	AuthHeader string `json:"auth_header,omitempty" validate:"required,min=32,max=32"`
}

type WebhookGetResponseDTO struct {
	config.Webhook
	LastRequestTime   time.Time `json:"time"`
	LastRequestStatus string    `json:"status"`
}

type WebhookAttribute struct {
	Key   string `json:"key" validate:"required"`
	Value string `json:"value" validate:"required"`
}

func (d *database) GetWebhookLastRequest(id string) (string, error) {
	return InternalConfig.Webhooks.LastRequests.Data().Key(id).Get(context.Background(), d.etcd)
}

func (d *database) GetWebhooks() (hooks []WebhookGetResponseDTO, err error) {

	result, err := InternalConfig.Webhooks.Active().List(context.Background(), d.etcd, clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	// otherwise json returns null
	hooks = make([]WebhookGetResponseDTO, 0, len(result.Values))

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then := txn.Then()

	type lastRequestDataHandles struct {
		time   *tetcd.GetHandle[time.Time]
		status *tetcd.GetHandle[string]
	}

	handles := make([]lastRequestDataHandles, 0, len(result.Order))

	for _, id := range result.Order {
		hooks = append(hooks, WebhookGetResponseDTO{Webhook: result.Values[id]})

		handles = append(handles,
			lastRequestDataHandles{
				time: tetcd.GetTx(then,
					InternalConfig.Webhooks.LastRequests.Time().Key(id),
					clientv3.WithRev(result.Rev),
				),

				status: tetcd.GetTx(then,
					InternalConfig.Webhooks.LastRequests.Status().Key(id),
					clientv3.WithRev(result.Rev),
				),
			})
	}

	err = txn.Commit()
	// we'll just have no last_request times so this isnt critical
	// intentional == nil
	if err == nil {
		for i := range handles {

			status, err := handles[i].status.Value()
			if err != nil {
				log.Info().Err(err).Msg("could not fetch last request status from webhook")
				continue
			}
			time, err := handles[i].time.Value()
			if err != nil {
				log.Info().Err(err).Msg("could not fetch last request time from webhook")
				continue
			}

			// As we're generating the txn list in order of the hooks we can do this. Its bad code and Im sure it'll blow up, but hey. Funni
			hooks[i].LastRequestTime = time
			hooks[i].LastRequestStatus = status
		}
	}

	return hooks, nil
}

func (d *database) CheckWebhookAuth(id, authHeader string) bool {
	if len(id) == 0 || len(authHeader) == 0 || len(authHeader) < 32 || len(id) < 32 {
		return false
	}

	key, err := d.generateWebhookSecret(id, authHeader)
	if err != nil {
		return false
	}

	resp, err := InternalConfig.Webhooks.Auth().Key(id).Get(context.Background(), d.etcd)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(resp), []byte(key)) == 1
}

func (d *database) WebhookRecordLastRequest(id, authHeader, request string) error {
	if !d.CheckWebhookAuth(id, authHeader) {
		return fmt.Errorf("webhook authorisation failed, or webhook did not exist")
	}

	if len(request) > 4096 {
		return fmt.Errorf("storing webhook request encountered an error, input was too big >4096 bytes")
	}

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then, elseHandle := txn.Conditional(clientv3util.KeyExists(InternalConfig.Webhooks.Active().Key(id).Key()))

	activeHandle := tetcd.GetTx(then, InternalConfig.Webhooks.Active().Key(id))
	tetcd.PutTx(then, InternalConfig.Webhooks.LastRequests.Data().Key(id), request)
	tetcd.PutTx(then, InternalConfig.Webhooks.LastRequests.Time().Key(id), time.Now())

	failureTxn := tetcd.SubTx(elseHandle)
	failureThen, _ := failureTxn.Conditional(clientv3util.KeyExists(InternalConfig.Webhooks.Temporary().Key(id).Key()))

	tetcd.PutTx(failureThen, InternalConfig.Webhooks.LastRequests.Data().Key(id), request)

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	if txn.Succeeded() {

		hookSettings, err := activeHandle.Value()
		if err != nil {
			return fmt.Errorf("failed to unmarshal webhook settings: %w", err)
		}

		go d.actionWebhook(hookSettings, &request)
		return nil

	}

	if !failureTxn.Succeeded() {
		return fmt.Errorf("webhook not found")
	}

	return nil
}

func (d *database) actionWebhook(hook config.Webhook, request *string) {

	var c map[string]any

	err := json.Unmarshal([]byte(*request), &c)
	if err != nil {
		d.RaiseError(fmt.Errorf("could not parse json webhook for %q: %w", hook.ID, err), nil)
		return
	}

	suppliedAttrbutes := Unpack("", c)

	var (
		DeviceIP  string
		DeviceTag string

		Username string

		Token string
	)

	for _, i := range suppliedAttrbutes {
		if hook.JsonAttributeRoles.AsDeviceIP == i.Key {
			DeviceIP = i.Value
			continue
		}

		if hook.JsonAttributeRoles.AsDeviceTag == i.Key {
			DeviceTag = i.Value
			continue
		}

		if hook.JsonAttributeRoles.AsUsername == i.Key {
			Username = i.Value
			continue
		}

		if hook.JsonAttributeRoles.AsRegistrationToken == i.Key {
			Token = i.Value
			continue
		}

	}

	switch hook.Action {

	case config.CreateRegistrationToken:

		err = d.AddRegistrationToken(Token, Username, "", "", nil, 1, DeviceTag)

	case config.DeleteDevice:
		if DeviceIP != "" {
			err = d.DeleteDevice(DeviceIP)
		} else {
			err = d.DeleteDeviceByTag(DeviceTag)
		}

	case config.DeleteUser:
		err = d.DeleteUser(Username)
	}

	status := "OK"
	if err != nil {

		status = err.Error()
		log.Error().Err(err).Str("action", string(hook.Action)).Str("hook_id", hook.ID).Msg("failed to action webhook")
		d.RaiseError(fmt.Errorf("unable to do %q via webhook %q as error occured: %w", hook.Action, hook.ID, err), nil)
	}

	InternalConfig.Webhooks.LastRequests.Status().Key(hook.ID).Put(context.Background(),
		d.etcd, status)
}

func (d *database) CreateWebhook(webhook WebhookCreateRequestDTO) error {
	validate := validator.New(validator.WithRequiredStructEnabled())

	if err := validate.Struct(webhook); err != nil {
		return fmt.Errorf("validation of new webhook failed: %w", err)
	}

	secret, err := d.generateWebhookSecret(webhook.ID, webhook.AuthHeader)
	if err != nil {
		return fmt.Errorf("could not store auth materical for web hook: %w", err)
	}

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then := txn.Then()
	tetcd.DeleteTx(then, InternalConfig.Webhooks.Temporary().Key(webhook.ID), clientv3.WithPrefix())
	tetcd.PutTx(then, InternalConfig.Webhooks.Auth().Key(webhook.ID), secret) // clears the lease that was created for the temporary webhook
	tetcd.PutTx(then, InternalConfig.Webhooks.Active().Key(webhook.ID), webhook.Webhook)

	return txn.Commit()

}

func (d *database) CreateTempWebhook() (string, string, error) {
	lease, err := clientv3.NewLease(d.etcd).Grant(context.Background(), 30*60)
	if err != nil {
		return "", "", err
	}

	var temp WebhookCreateRequestDTO

	temp.ID, err = utils.GenerateRandomHex(16)
	if err != nil {
		return "", "", fmt.Errorf("unable to generate random id for temp webhook: %w", err)
	}

	authHeader, err := utils.GenerateRandomHex(16)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate auth header: %w", err)
	}

	secret, err := d.generateWebhookSecret(temp.ID, authHeader)
	if err != nil {
		return "", "", fmt.Errorf("could not use generated value as auth header: %w", err)
	}

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then := txn.Then()

	tetcd.PutTx(then, InternalConfig.Webhooks.Temporary().Key(temp.ID), temp.Webhook, clientv3.WithLease(lease.ID))
	tetcd.PutTx(then, InternalConfig.Webhooks.Auth().Key(temp.ID), secret, clientv3.WithLease(lease.ID))

	if err = txn.Commit(); err != nil {
		return "", "", fmt.Errorf("failed to commit transaction for temp webhook: %w", err)
	}

	return temp.ID, authHeader, err
}

func (d *database) DeleteWebhooks(ids []string) error {

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then := txn.Then()

	for _, id := range ids {

		tetcd.DeleteTx(then, InternalConfig.Webhooks.Active().Key(id), clientv3.WithPrefix())
		tetcd.DeleteTx(then, InternalConfig.Webhooks.Auth().Key(id), clientv3.WithPrefix())
		// this is a little gross, it might be better to make last requests a map
		tetcd.DeleteTx(then, InternalConfig.Webhooks.LastRequests.Data().Key(id), clientv3.WithPrefix())
		tetcd.DeleteTx(then, InternalConfig.Webhooks.LastRequests.Status().Key(id), clientv3.WithPrefix())
		tetcd.DeleteTx(then, InternalConfig.Webhooks.LastRequests.Time().Key(id), clientv3.WithPrefix())
	}

	return txn.Commit()
}

func Unpack(parent string, c map[string]any) []WebhookAttribute {

	output := []WebhookAttribute{}

	if parent != "" {
		parent += "."
	}

	for k, v := range c {

		if innerAttributes, ok := v.(map[string]any); ok {
			output = append(output, Unpack(k, innerAttributes)...)
		} else {

			output = append(output, WebhookAttribute{parent + k, fmt.Sprintf("%v", v)})
		}

	}

	return output

}
