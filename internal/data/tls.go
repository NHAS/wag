package data

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"go.etcd.io/etcd/client/pkg/v3/types"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/clientv3util"
)

type WebServer string

const (
	Tunnel       = WebServer("tunnel")
	ManagementUI = WebServer("tunnel")
	Public       = WebServer("tunnel")

	TLSPrefix         = "wag-tls-"
	CertificatesKey   = TLSPrefix + "certificates-"
	UpdateCertHoldKey = TLSPrefix + "hold"
	PinAcmeQuerierKey = TLSPrefix + "force-acme-from-node"

	AcmeTime = 2 * 60
)

func PinNodeToAcmeDuties(node types.ID) error {
	_, err := etcd.Put(context.Background(), PinAcmeQuerierKey, node.String())
	return err
}

func UnpinAcmeDuties() error {
	_, err := etcd.Delete(context.Background(), PinAcmeQuerierKey)
	return err
}

type Certificate struct {
	Certificate []byte
	PrivateKey  []byte `sensitive:"true"`
}

type certificateJSON struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

// MarshalJSON implements the json.Marshaler interface
func (c Certificate) MarshalJSON() ([]byte, error) {
	return json.Marshal(certificateJSON{
		Certificate: base64.StdEncoding.EncodeToString(c.Certificate),
		PrivateKey:  base64.StdEncoding.EncodeToString(c.PrivateKey),
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (c *Certificate) UnmarshalJSON(data []byte) error {
	var jsonData certificateJSON
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return err
	}

	cert, err := base64.StdEncoding.DecodeString(jsonData.Certificate)
	if err != nil {
		return err
	}

	key, err := base64.StdEncoding.DecodeString(jsonData.PrivateKey)
	if err != nil {
		return err
	}

	c.Certificate = cert
	c.PrivateKey = key
	return nil
}

func AllowToRenew() (bool, error) {
	lease, err := clientv3.NewLease(etcd).Grant(context.Background(), AcmeTime)
	if err != nil {
		return false, err
	}

	txn := etcd.Txn(context.Background())
	txn.If(
		clientv3util.KeyMissing(UpdateCertHoldKey),
	).Then(
		clientv3.OpPut(UpdateCertHoldKey, GetServerID().String(), clientv3.WithLease(lease.ID)),
	)

	resp, err := txn.Commit()
	if err != nil {
		return false, err
	}

	// This node won the race, so now it can do acme (and will not be stomped on for <AcmeTime> seconds)
	return resp.Succeeded, nil
}

func SetCertificate(forWhat WebServer, certificate, privateKey []byte) error {

	newCert := Certificate{
		Certificate: certificate,
		PrivateKey:  privateKey,
	}

	data, err := json.Marshal(newCert)
	if err != nil {
		return fmt.Errorf("failed to marshal new certificate: %w", err)
	}

	_, err = etcd.Put(context.Background(), CertificatesKey+string(forWhat), string(data))

	return err
}

// deliberately no getter, so that we force the user to use the events system to update their certificates

// SupportsTLS Should only be used on startup, everywhere else use the events system to watch if certificates have been updated/created
func SupportsTLS(web WebServer) bool {

	certificates, err := etcd.Get(context.Background(), CertificatesKey+string(web))
	if err != nil {
		return false
	}

	if certificates.Count == 0 {
		return false
	}

	if len(certificates.Kvs) != 1 {
		return false
	}

	var jsonCert certificateJSON
	err = json.Unmarshal(certificates.Kvs[0].Value, &jsonCert)

	return err == nil
}
