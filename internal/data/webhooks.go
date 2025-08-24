package data

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"path"
	"time"

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
	WebhookAuthPrefix    = WebhooksPrefix + "auth/"
	TempWebhooksPrefix   = WebhooksPrefix + "webhooks/temp/"
	ActiveWebhooksPrefix = WebhooksPrefix + "webhooks/active/"
)

func (d *database) GetLastWebhookRequestPath(id string, additionals ...string) string {

	input := []string{
		WebhooksPrefix, "last_requests", id,
	}

	input = append(input, additionals...)

	result := path.Join(input...)
	if len(additionals) == 0 {
		result += "/"
	}

	return result
}

func (d *database) GetWebhookAuthPath(id, plainTextCredentials string) (string, error) {

	res, err := pbkdf2.Key(sha256.New, plainTextCredentials, []byte(id), 10, 32)
	if err != nil {
		return "", fmt.Errorf("unable to determine hash: %w", err)
	}

	result := path.Join(WebhookAuthPrefix, id, hex.EncodeToString(res))

	return result, nil
}

type Webhook struct {
	ID                 string                  `json:"id" validate:"required"`
	Action             string                  `json:"action" validate:"required,oneof=create_token delete_device delete_user"`
	JsonAttributeRoles WebhookAttributeMapping `json:"json_attribute_roles" validate:"required"`
}

type WebhookAttributeMapping struct {
	AsUsername          string `json:"as_username" validate:"omitempty,max=255,min=1"`
	AsDeviceTag         string `json:"as_device_tag" validate:"omitempty,max=255,min=1"`
	AsRegistrationToken string `json:"as_registration_token" validate:"omitempty,max=255,min=1"`
	AsDeviceIP          string `json:"as_device_ip" validate:"omitempty,max=255,min=1"`
}

type WebhookCreateRequestDTO struct {
	Webhook
	AuthHeader string `json:"auth_header,omitempty" validate:"required,min=32,max=32"`
}

type WebhookGetResponseDTO struct {
	Webhook
	LastRequestTime   time.Time `json:"time"`
	LastRequestStatus string    `json:"status"`
}

type WebhookAttribute struct {
	Key   string `json:"key" validate:"required"`
	Value string `json:"value" validate:"required"`
}

func (d *database) GetWebhookLastRequest(id string) (string, error) {
	return Get[string](d.etcd, d.GetLastWebhookRequestPath(id, "data"))
}

func (d *database) GetWebhook(id string) (WebhookGetResponseDTO, error) {
	return Get[WebhookGetResponseDTO](d.etcd, ActiveWebhooksPrefix+id)
}

func (d *database) GetWebhooks() (hooks []WebhookGetResponseDTO, err error) {

	response, err := d.etcd.Get(context.Background(), ActiveWebhooksPrefix, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	// otherwise json returns null
	hooks = []WebhookGetResponseDTO{}
	lastRequestOps := []clientv3.Op{}
	lastRequestStatusOps := []clientv3.Op{}
	for _, res := range response.Kvs {
		var hook WebhookGetResponseDTO
		err := json.Unmarshal(res.Value, &hook)
		if err != nil {
			return nil, err
		}

		lastRequestOps = append(lastRequestOps, clientv3.OpGet(d.GetLastWebhookRequestPath(hook.ID, "time"), clientv3.WithRev(response.Header.Revision)))
		lastRequestStatusOps = append(lastRequestStatusOps, clientv3.OpGet(d.GetLastWebhookRequestPath(hook.ID, "status"), clientv3.WithRev(response.Header.Revision)))

		hooks = append(hooks, hook)
	}

	resp, err := d.etcd.Txn(context.Background()).Then(lastRequestOps...).Commit()
	// we'll just have no last_request times so this isnt critical
	// intentional == nil
	if err == nil {
		for i := range resp.Responses {

			if len(resp.Responses[i].GetResponseRange().Kvs) == 0 {
				// webhook has never fired so ignore
				continue
			}

			var t time.Time
			err = json.Unmarshal(resp.Responses[i].GetResponseRange().Kvs[0].Value, &t)
			if err != nil {
				log.Printf("could not unmarshal last request time from webhook: %s: %v", string(resp.Responses[i].GetResponseRange().Kvs[0].Key), err)
				continue
			}

			// As we're generating the txn list in order of the hooks we can do this. Its bad code and Im sure it'll blow up, but hey. Funni
			hooks[i].LastRequestTime = t
		}
	}

	resp, err = d.etcd.Txn(context.Background()).Then(lastRequestStatusOps...).Commit()
	// we'll just have no last_request status' so this isnt critical
	// intentional == nil
	if err == nil {
		for i := range resp.Responses {

			if len(resp.Responses[i].GetResponseRange().Kvs) == 0 {
				// webhook has never fired so ignore
				continue
			}

			var status string
			err = json.Unmarshal(resp.Responses[i].GetResponseRange().Kvs[0].Value, &status)
			if err != nil {
				log.Println(string(resp.Responses[i].GetResponseRange().Kvs[0].Value))
				log.Printf("could not unmarshal last request status from webhook: %s: %v", string(resp.Responses[i].GetResponseRange().Kvs[0].Key), err)
				continue
			}

			// As we're generating the txn list in order of the hooks we can do this. Its bad code and Im sure it'll blow up, but hey. Funni
			hooks[i].LastRequestStatus = status
		}
	}

	return hooks, nil
}

func (d *database) CheckWebhookAuth(id, authHeader string) bool {
	if len(id) == 0 || len(authHeader) == 0 || len(authHeader) < 32 || len(id) < 32 {
		return false
	}

	path, err := d.GetWebhookAuthPath(id, authHeader)
	if err != nil {
		return false
	}

	resp, err := d.etcd.Get(context.Background(), path)
	if err != nil {
		return false
	}

	return len(resp.Kvs) == 1
}

func (d *database) WebhookRecordLastRequest(id, authHeader, request string) error {
	if !d.CheckWebhookAuth(id, authHeader) {
		return fmt.Errorf("webhook authorisation failed, or webhook did not exist")
	}

	if len(request) > 4096 {
		return fmt.Errorf("storing webhook request encountered an error, input was too big >4096 bytes")
	}

	requestBytes, _ := json.Marshal(request)

	timeBytes, _ := json.Marshal(time.Now())

	res, err := d.etcd.Txn(context.Background()).If(
		clientv3util.KeyExists(ActiveWebhooksPrefix+id),
	).Then(
		clientv3.OpGet(ActiveWebhooksPrefix+id),
		clientv3.OpPut(d.GetLastWebhookRequestPath(id, "data"), string(requestBytes)),
		clientv3.OpPut(d.GetLastWebhookRequestPath(id, "time"), string(timeBytes)),
	).Else(
		clientv3.OpTxn(
			[]clientv3.Cmp{
				clientv3util.KeyExists(TempWebhooksPrefix + id),
			},
			[]clientv3.Op{
				clientv3.OpPut(d.GetLastWebhookRequestPath(id, "data"), string(requestBytes)),
			},
			nil,
		),
	).Commit()

	if res.Succeeded {

		if len(res.Responses) != 3 {
			return fmt.Errorf("unable read response incorrect size: %d", len(res.Responses))
		}

		if len(res.Responses[0].GetResponseRange().Kvs) != 1 {
			return fmt.Errorf("incorrect key value size for getting webhook action: %q", id)
		}

		var hookSettings Webhook
		err = json.Unmarshal(res.Responses[0].GetResponseRange().Kvs[0].Value, &hookSettings)
		if err != nil {
			return fmt.Errorf("unable to unmarshal webhook settings: %w", err)
		}

		go d.actionWebhook(hookSettings, &request)

	} else if !res.Responses[0].GetResponseTxn().Succeeded {
		return fmt.Errorf("webhook not found")
	}

	return err
}

func (d *database) actionWebhook(hook Webhook, request *string) {

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

	status := "OK"
	if err != nil {
		status = err.Error()
		d.RaiseError(fmt.Errorf("unable to do %q via webhook %q as error occured: %w", hook.Action, hook.ID, err), nil)
	}

	Set(d.etcd, d.GetLastWebhookRequestPath(hook.ID, "status"), true, status)
}

func (d *database) CreateWebhook(webhook WebhookCreateRequestDTO) error {
	validate := validator.New(validator.WithRequiredStructEnabled())

	if err := validate.Struct(webhook); err != nil {
		return fmt.Errorf("validation of new webhook failed: %w", err)
	}

	credPath, err := d.GetWebhookAuthPath(webhook.ID, webhook.AuthHeader)
	if err != nil {
		return fmt.Errorf("could not store auth materical for web hook: %w", err)
	}

	b, _ := json.Marshal(webhook)

	_, err = d.etcd.Txn(context.Background()).Then(
		clientv3.OpDelete(TempWebhooksPrefix+webhook.ID, clientv3.WithPrefix()),
		clientv3.OpPut(credPath, "\"\""), // this clears the lease (hopefully)
		clientv3.OpPut(ActiveWebhooksPrefix+webhook.ID, string(b)),
	).Commit()

	return err
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

	authPath, err := d.GetWebhookAuthPath(temp.ID, authHeader)
	if err != nil {
		return "", "", fmt.Errorf("could not use generated value as auth header: %w", err)
	}

	tempBytes, _ := json.Marshal(temp)

	_, err = d.etcd.Txn(context.Background()).Then(
		clientv3.OpPut(TempWebhooksPrefix+temp.ID, string(tempBytes), clientv3.WithLease(lease.ID)),
		clientv3.OpPut(authPath, "\"\"", clientv3.WithLease(lease.ID)),
	).Commit()

	return temp.ID, authHeader, err
}

func (d *database) DeleteWebhooks(ids []string) error {

	var ops []clientv3.Op

	for _, id := range ids {
		ops = append(ops,
			clientv3.OpDelete(ActiveWebhooksPrefix+id, clientv3.WithPrefix()),
			clientv3.OpDelete(d.GetLastWebhookRequestPath(id), clientv3.WithPrefix()),
			clientv3.OpDelete(WebhookAuthPrefix+id, clientv3.WithPrefix()),
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
