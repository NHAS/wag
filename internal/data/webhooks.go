package data

import (
	"context"
	"encoding/json"
	"fmt"
	"path"

	"github.com/NHAS/wag/internal/utils"
	"github.com/go-playground/validator/v10"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/clientv3util"
)

const (
	CreateRegistrationToken = "create_token"
	DeleteDevice            = "delete_device"
	DeleteUser              = "delete_user"

	WebhooksPrefix       = "wag-webhooks/"
	TempWebhooksPrefix   = WebhooksPrefix + "webhooks/temp/"
	ActiveWebhooksPrefix = WebhooksPrefix + "webhooks/active/"
)

func (d *database) GetLastWebhookRequestPath(id string) string {
	return path.Join(WebhooksPrefix, "last_requests", id)
}

type WebhookAttributeMapping struct {
	AsUsername          string `json:"as_username" validate:"omitempty,max=255,min=1"`
	AsDeviceTag         string `json:"as_device_tag" validate:"omitempty,max=255,min=1"`
	AsRegistrationToken string `json:"as_registration_token" validate:"omitempty,max=255,min=1"`
	AsDeviceIP          string `json:"as_device_ip" validate:"omitempty,omitempty,max=255,min=1"`
}

type WebhookDTO struct {
	ID                 string                  `json:"id" validate:"required"`
	Action             string                  `json:"action" validate:"required,oneof=create_token delete_device delete_user"`
	JsonAttributeRoles WebhookAttributeMapping `json:"json_attribute_roles" validate:"required"`
}

type WebhookAttribute struct {
	Key   string `json:"key" validate:"required"`
	Value string `json:"value" validate:"required"`
}

func (d *database) GetWebhook(id string) (WebhookDTO, error) {
	return Get[WebhookDTO](d.etcd, ActiveWebhooksPrefix+id)
}

func (d *database) GetWebhookLastRequest(id string) (string, error) {
	return Get[string](d.etcd, d.GetLastWebhookRequestPath(id))
}

func (d *database) WebhookExists(id string) bool {
	res, err := d.etcd.Txn(context.Background()).
		If(
			clientv3util.KeyExists(ActiveWebhooksPrefix + id),
		).Commit()

	if err != nil {
		return false
	}

	if res.Succeeded {
		return true
	}

	res, err = d.etcd.Txn(context.Background()).
		If(
			clientv3util.KeyExists(TempWebhooksPrefix + id),
		).Commit()

	if err != nil {
		return false
	}

	return res.Succeeded
}

func (d *database) GetWebhooks() (hooks []WebhookDTO, err error) {

	response, err := d.etcd.Get(context.Background(), ActiveWebhooksPrefix, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
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

func (d *database) WebhookRecordLastRequest(id, request string) error {

	if len(request) > 4096 {
		return fmt.Errorf("storing webhook request encountered an error, input was too big >4096 bytes")
	}

	requestBytes, _ := json.Marshal(request)

	res, err := d.etcd.Txn(context.Background()).If(
		clientv3util.KeyExists(ActiveWebhooksPrefix+id),
	).Then(
		clientv3.OpPut(d.GetLastWebhookRequestPath(id), string(requestBytes)),
		clientv3.OpGet(ActiveWebhooksPrefix+id),
	).Else(
		clientv3.OpTxn(
			[]clientv3.Cmp{
				clientv3util.KeyExists(TempWebhooksPrefix + id),
			},
			[]clientv3.Op{
				clientv3.OpPut(d.GetLastWebhookRequestPath(id), string(requestBytes)),
			},
			nil,
		),
	).Commit()

	if res.Succeeded {

		if len(res.Responses) != 2 {
			return fmt.Errorf("unable read response incorrect size: %d", len(res.Responses))
		}

		if len(res.Responses[1].GetResponseRange().Kvs) != 1 {
			return fmt.Errorf("incorrect key value size for getting webhook action: %q", id)
		}

		var hookSettings WebhookDTO
		err = json.Unmarshal(res.Responses[1].GetResponseRange().Kvs[0].Value, &hookSettings)
		if err != nil {
			return fmt.Errorf("unable to unmarshal webhook settings: %w", err)
		}

		go d.actionWebhook(hookSettings, &request)
	}

	return err
}

func (d *database) actionWebhook(hook WebhookDTO, request *string) {

	var c map[string]any

	err := json.Unmarshal([]byte(*request), &c)
	if err != nil {
		d.RaiseError(fmt.Errorf("could not parse json webhook for %q: %w", hook.ID, err), nil)
		return
	}

	suppliedAttrbutes := Unpack("", c)

	var (
		DeviceIP string
		//DeviceTag string

		Username string

		Token string
	)

	for _, i := range suppliedAttrbutes {
		if hook.JsonAttributeRoles.AsDeviceIP == i.Key {
			DeviceIP = i.Value
			continue
		}

		// if hook.JsonAttributeRoles.AsDeviceTag == i.Key {
		// 	DeviceTag = i.Value
		// 	continue
		// }

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

	case CreateRegistrationToken:

		err = d.AddRegistrationToken(Token, Username, "", "", nil, 1)

	case DeleteDevice:

		err = d.DeleteDevice(Username, DeviceIP)

	case DeleteUser:
		err = d.DeleteUser(Username)
	}

	if err != nil {
		d.RaiseError(fmt.Errorf("unable to do %q via webhook %q as error occured: %w", hook.Action, hook.ID, err), nil)
	}
}

func (d *database) CreateWebhook(webhook WebhookDTO) error {
	validate := validator.New(validator.WithRequiredStructEnabled())

	if err := validate.Struct(webhook); err != nil {
		return fmt.Errorf("validation of new webhook failed: %w", err)
	}

	d.etcd.Delete(context.Background(), TempWebhooksPrefix+webhook.ID)

	return Set(d.etcd, ActiveWebhooksPrefix+webhook.ID, false, webhook)
}

func (d *database) CreateTempWebhook() (string, error) {
	lease, err := clientv3.NewLease(d.etcd).Grant(context.Background(), 30*60)
	if err != nil {
		return "", err
	}

	var temp WebhookDTO

	temp.ID, err = utils.GenerateRandomHex(16)
	if err != nil {
		return "", fmt.Errorf("unable to generate random id for temp webhook: %w", err)
	}

	err = Set(d.etcd, TempWebhooksPrefix+temp.ID, false, temp, clientv3.WithLease(lease.ID))

	return temp.ID, err
}

func (d *database) DeleteWebhooks(ids []string) error {

	var ops []clientv3.Op

	for _, id := range ids {
		ops = append(ops,
			clientv3.OpDelete(ActiveWebhooksPrefix+id),
			clientv3.OpDelete(d.GetLastWebhookRequestPath(id)),
		)
	}

	_, err := d.etcd.Txn(context.Background()).Then(ops...).Commit()
	return err
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
