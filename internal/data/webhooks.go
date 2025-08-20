package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/NHAS/wag/internal/utils"
	"github.com/go-playground/validator/v10"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	CreateRegistrationToken = "create_token"
	DeleteDevice            = "delete_device"
	DeleteUser              = "delete_user"
)

type WebhookAttributeMapping struct {
	AsUsername          string `json:"as_username" validate:"omitempty,max=255,min=1"`
	AsDeviceTag         string `json:"as_device_tag" validate:"omitempty,max=255,min=1"`
	AsRegistrationToken string `json:"as_registration_token" validate:"omitempty,max=255,min=1"`
}

type WebhookDTO struct {
	ID                   string                  `json:"id" validate:"required"`
	Action               string                  `json:"action" validate:"required,oneof=create_token delete_device delete_user"`
	JsonAttributeMapping WebhookAttributeMapping `json:"json_attribute_mapping" validate:"required"`
}

type Webhook struct {
	WebhookDTO
	Key string
}

type WebhookAttribute struct {
	Key   string `json:"key" validate:"required"`
	Value string `json:"value" validate:"required"`
}

type tempWebhook struct {
	ID           string
	Key          string
	IncomingData []byte
}

func (d *database) GetWebhook(id string) (Webhook, error) {
	return Get[Webhook](d.etcd, WebhooksPrefix+id)
}

func (d *database) GetWebhooks() (hooks []WebhookDTO, err error) {

	response, err := d.etcd.Get(context.Background(), WebhooksPrefix, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	// otherwise json returns null
	hooks = []WebhookDTO{}
	for _, res := range response.Kvs {
		var hook WebhookDTO
		err := json.Unmarshal(res.Value, &hook)
		if err != nil {
			return nil, err
		}

		hooks = append(hooks, hook)
	}

	return hooks, nil
}

func (d *database) CreateWebhook(id, action string, mapping WebhookAttributeMapping) error {
	ret, err := Get[tempWebhook](d.etcd, TempWebhooksPrefix+id)
	if err != nil {
		return fmt.Errorf("cannot create webhook without testing webhook: %w", err)
	}

	var webhook Webhook
	webhook.ID = ret.ID
	webhook.Key = ret.Key
	webhook.JsonAttributeMapping = mapping
	webhook.Action = action

	validate := validator.New(validator.WithRequiredStructEnabled())

	if err := validate.Struct(webhook); err != nil {
		return fmt.Errorf("validation of new webhook failed: %w", err)
	}

	return Set(d.etcd, WebhooksPrefix+webhook.ID, false, webhook)
}

func (d *database) CreateTempWebhook() (string, error) {
	lease, err := clientv3.NewLease(d.etcd).Grant(context.Background(), 30*60)
	if err != nil {
		return "", err
	}

	var temp tempWebhook
	temp.Key, err = utils.GenerateRandomHex(32)
	if err != nil {
		return "", fmt.Errorf("unable to generate random key for temp webhook: %w", err)
	}
	temp.ID, err = utils.GenerateRandomHex(16)
	if err != nil {
		return "", fmt.Errorf("unable to generate random id for temp webhook: %w", err)
	}

	err = Set(d.etcd, TempWebhooksPrefix+temp.ID, false, temp, clientv3.WithLease(lease.ID))

	return temp.ID, err
}

func (d *database) UpdateTempWebhook(id string, content []byte) error {

	key := TempWebhooksPrefix + id

	return d.doSafeUpdate(context.Background(), key, false, func(gr *clientv3.GetResponse) (value string, err error) {
		if len(gr.Kvs) != 1 {
			return "", errors.New("temp webhook has multiple keys")
		}

		var newTemp tempWebhook
		err = json.Unmarshal(gr.Kvs[0].Value, &newTemp)
		if err != nil {
			return "", err
		}

		newTemp.IncomingData = content

		b, _ := json.Marshal(newTemp)

		return string(b), err
	})

}

func (d *database) DeleteWebhooks(ids []string) error {

	var ops []clientv3.Op

	for _, id := range ids {
		ops = append(ops, clientv3.OpDelete(id))
	}

	_, err := d.etcd.Txn(context.Background()).Then(ops...).Commit()
	return err
}
