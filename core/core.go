// Package core handles the main operations of the Red October server.
//
// Copyright (c) 2013 CloudFlare, Inc.

package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/cloudflare/redoctober/cryptor"
	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/order"
	"github.com/cloudflare/redoctober/passvault"
)

var (
	crypt   cryptor.Cryptor
	records passvault.Records
	cache   keycache.Cache
	orderer order.Orderer
)

// Each of these structures corresponds to the JSON expected on the
// correspondingly named URI (e.g. the delegate structure maps to the
// JSON that should be sent on the /delegate URI and it is handled by
// the Delegate function below).

type CreateRequest struct {
	Name     string
	Password string
}

type SummaryRequest struct {
	Name     string
	Password string
}

type PurgeRequest struct {
	Name     string
	Password string
}

type DelegateRequest struct {
	Name     string
	Password string

	Uses   int
	Time   string
	Users  []string
	Labels []string
}

type PasswordRequest struct {
	Name     string
	Password string

	NewPassword string
	Email       string
}

type EncryptRequest struct {
	Name     string
	Password string

	Owners      []string
	LeftOwners  []string
	RightOwners []string
	Predicate   string

	Data []byte

	Labels []string
}

type DecryptRequest struct {
	Name     string
	Password string

	Data []byte
}

type OwnersRequest struct {
	Data []byte
}

type ModifyRequest struct {
	Name     string
	Password string

	ToModify string
	Command  string
}

type ExportRequest struct {
	Name     string
	Password string
}

type OrderRequest struct {
	Name     string
	Password string

	Data  []byte
	Label string
}

type OrderInfoRequest struct {
	Name     string
	Password string

	OrderNum string
}
type OrderOutstandingRequest struct {
	Name     string
	Password string
}

// These structures map the JSON responses that will be sent from the API

type ResponseData struct {
	Status   string
	Response []byte `json:",omitempty"`
}

type SummaryData struct {
	Status string
	Live   map[string]keycache.ActiveUser
	All    map[string]passvault.Summary
}

type DecryptWithDelegates struct {
	Data      []byte
	Secure    bool
	Delegates []string
}

type OwnersData struct {
	Status string
	Owners []string
}

// Helper functions that create JSON responses sent by core

func jsonStatusOk() ([]byte, error) {
	return json.Marshal(ResponseData{Status: "ok"})
}
func jsonStatusError(err error) ([]byte, error) {
	return json.Marshal(ResponseData{Status: err.Error()})
}
func jsonSummary() ([]byte, error) {
	return json.Marshal(SummaryData{Status: "ok", Live: cache.GetSummary(), All: records.GetSummary()})
}
func jsonResponse(resp []byte) ([]byte, error) {
	return json.Marshal(ResponseData{Status: "ok", Response: resp})
}

// validateUser checks that the username and password passed in are
// correct. If admin is true, the user must be an admin as well.
func validateUser(name, password string, admin bool) error {
	if records.NumRecords() == 0 {
		return errors.New("Vault is not created yet")
	}

	pr, ok := records.GetRecord(name)
	if !ok {
		return errors.New("User not present")
	}

	if err := pr.ValidatePassword(password); err != nil {
		return err
	}

	if admin && !pr.IsAdmin() {
		return errors.New("Admin required")
	}

	return nil
}

// validateName checks that the username and password pass the minimal
// validation check
func validateName(name, password string) error {
	if name == "" {
		return errors.New("User name must not be blank")
	}
	if password == "" {
		return errors.New("Password must be at least one character")
	}

	return nil
}

// Init reads the records from disk from a given path
func Init(vaultPath, smtpPath string) error {
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.init failed: %v", err)
		} else {
			log.Printf("core.init success: vaultPath=%s", vaultPath)
		}
	}()

	if records, err = passvault.InitFrom(vaultPath); err != nil {
		err = fmt.Errorf("failed to load password vault %s: %s", vaultPath, err)
	}

	// Without this, we will be attempting to enter into a nil map
	orderer.PrepareOrders()

	if smtpPath != "" {
		orderer.Notifier = *new(order.SmtpAuth)
		smtpBytes, err := ioutil.ReadFile(smtpPath)
		if err != nil {
			return err
		}
		err = json.Unmarshal(smtpBytes, &orderer.Notifier)
		if err != nil {
			return err
		}

	}
	cache = keycache.Cache{UserKeys: make(map[string]keycache.ActiveUser)}
	crypt = cryptor.New(&records, &cache, orderer)

	return err
}

// Create processes a create request.
func Create(jsonIn []byte) ([]byte, error) {
	var s CreateRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.create failed: user=%s %v", s.Name, err)
		} else {
			log.Printf("core.create success: user=%s", s.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if records.NumRecords() != 0 {
		err = errors.New("Vault is already created")
		return jsonStatusError(err)
	}

	// Validate the Name and Password as valid
	if err = validateName(s.Name, s.Password); err != nil {
		return jsonStatusError(err)
	}

	if _, err = records.AddNewRecord(s.Name, s.Password, true, passvault.DefaultRecordType); err != nil {
		return jsonStatusError(err)
	}

	return jsonStatusOk()
}

// Summary processes a summary request.
func Summary(jsonIn []byte) ([]byte, error) {
	var s SummaryRequest
	var err error
	cache.Refresh()

	defer func() {
		if err != nil {
			log.Printf("core.summary failed: user=%s %v", s.Name, err)
		} else {
			log.Printf("core.summary success: user=%s", s.Name)
		}
	}()

	if err := json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if records.NumRecords() == 0 {
		err = errors.New("vault has not been created")
		return jsonStatusError(err)
	}

	if err := validateUser(s.Name, s.Password, false); err != nil {
		return jsonStatusError(err)
	}

	return jsonSummary()
}

// Purge processes a delegation purge request.
func Purge(jsonIn []byte) ([]byte, error) {
	var s PurgeRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.purge failed: user=%s %v", s.Name, err)
		} else {
			log.Printf("core.purge success: user=%s", s.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if records.NumRecords() == 0 {
		err = errors.New("vault has not been created")
		return jsonStatusError(err)
	}

	// Validate the Name and Password as valid and admin
	if err = validateUser(s.Name, s.Password, true); err != nil {
		return jsonStatusError(err)
	}

	cache.FlushCache()
	return jsonStatusOk()
}

// Delegate processes a delegation request.
func Delegate(jsonIn []byte) ([]byte, error) {
	var s DelegateRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.delegate failed: user=%s %v", s.Name, err)
		} else {
			log.Printf("core.delegate success: user=%s uses=%d time=%s users=%v labels=%v", s.Name, s.Uses, s.Time, s.Users, s.Labels)
		}
	}()

	if err = json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if records.NumRecords() == 0 {
		err = errors.New("Vault is not created yet")
		return jsonStatusError(err)
	}

	// Validate the Name and Password as valid
	if err = validateName(s.Name, s.Password); err != nil {
		return jsonStatusError(err)
	}

	// Find password record for user and verify that their password
	// matches. If not found then add a new entry for this user.

	pr, found := records.GetRecord(s.Name)
	if found {
		if err = pr.ValidatePassword(s.Password); err != nil {
			return jsonStatusError(err)
		}
	} else {
		if pr, err = records.AddNewRecord(s.Name, s.Password, false, passvault.DefaultRecordType); err != nil {
			return jsonStatusError(err)
		}
	}

	// add signed-in record to active set
	if err = cache.AddKeyFromRecord(pr, s.Name, s.Password, s.Users, s.Labels, s.Uses, s.Time); err != nil {
		return jsonStatusError(err)
	}

	// if something was delegated, check to see the current orders and
	// increment it.
	orderNums := order.GenerateNums(s.Users, s.Labels)
	for _, orderNum := range orderNums {
		if ord, ok := orderer.Orders[orderNum]; ok {
			ord.Delegated++
			orderer.Orders[orderNum] = ord
		}
	}
	return jsonStatusOk()
}

// Password processes a password change request.
func Password(jsonIn []byte) ([]byte, error) {
	var err error
	var s PasswordRequest

	defer func() {
		if err != nil {
			log.Printf("core.password failed: user=%s %v", s.Name, err)
		} else {
			log.Printf("core.password success: user=%s", s.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if records.NumRecords() == 0 {
		err = errors.New("Vault is not created yet")
		return jsonStatusError(err)
	}

	// add signed-in record to active set
	err = records.ChangePassword(s.Name, s.Password, s.NewPassword, s.Email)
	if err != nil {
		return jsonStatusError(err)
	}

	return jsonStatusOk()
}

// Encrypt processes an encrypt request.
func Encrypt(jsonIn []byte) ([]byte, error) {
	var s EncryptRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.encrypt failed: user=%s size=%d %v", s.Name, len(s.Data), err)
		} else {
			log.Printf("core.encrypt success: user=%s size=%d", s.Name, len(s.Data))
		}
	}()

	err = json.Unmarshal(jsonIn, &s)
	if err != nil {
		return jsonStatusError(err)
	}

	if err = validateUser(s.Name, s.Password, false); err != nil {
		return jsonStatusError(err)
	}

	access := cryptor.AccessStructure{
		Names:      s.Owners,
		LeftNames:  s.LeftOwners,
		RightNames: s.RightOwners,
		Predicate:  s.Predicate,
	}

	resp, err := crypt.Encrypt(s.Data, s.Labels, access)
	if err != nil {
		return jsonStatusError(err)
	}
	return jsonResponse(resp)
}

// Decrypt processes a decrypt request.
func Decrypt(jsonIn []byte) ([]byte, error) {
	var s DecryptRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.decrypt failed: user=%s %v", s.Name, err)
		} else {
			log.Printf("core.decrypt success: user=%s", s.Name)
		}
	}()

	err = json.Unmarshal(jsonIn, &s)
	if err != nil {
		return jsonStatusError(err)
	}

	err = validateUser(s.Name, s.Password, false)
	if err != nil {
		return jsonStatusError(err)
	}

	data, allLabels, names, secure, err := crypt.Decrypt(s.Data, s.Name)
	if err != nil {
		return jsonStatusError(err)
	}

	resp := &DecryptWithDelegates{
		Data:      data,
		Secure:    secure,
		Delegates: names,
	}

	out, err := json.Marshal(resp)
	if err != nil {
		return jsonStatusError(err)
	}

	// If everything decrpyted properly. Check to
	// see if there was an order for it and kill it.
	orderNums := order.GenerateNums([]string{s.Name}, allLabels)
	for _, orderNum := range orderNums {
		if _, ok := orderer.Orders[orderNum]; ok {
			owners, err := crypt.GetOwners(s.Data)
			if err == nil {
				contacts := crypt.GetContacts(owners)
				go orderer.Notifier.Notify(contacts, orderNum, s.Name, order.OrderFulfilled)
			}
			delete(orderer.Orders, orderNum)
		}
	}

	return jsonResponse(out)
}

// Modify processes a modify request.
func Modify(jsonIn []byte) ([]byte, error) {
	var s ModifyRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.modify failed: user=%s target=%s command=%s %v", s.Name, s.ToModify, s.Command, err)
		} else {
			log.Printf("core.modify success: user=%s target=%s command=%s", s.Name, s.ToModify, s.Command)
		}
	}()

	err = json.Unmarshal(jsonIn, &s)
	if err != nil {
		return jsonStatusError(err)
	}

	if err = validateUser(s.Name, s.Password, true); err != nil {
		return jsonStatusError(err)
	}

	if _, ok := records.GetRecord(s.ToModify); !ok {
		err = errors.New("core: record to modify missing")
		return jsonStatusError(err)
	}

	if s.Name == s.ToModify {
		err = errors.New("core: cannot modify own record")
		return jsonStatusError(err)
	}

	switch s.Command {
	case "delete":
		err = records.DeleteRecord(s.ToModify)
	case "revoke":
		err = records.RevokeRecord(s.ToModify)
	case "admin":
		err = records.MakeAdmin(s.ToModify)
	default:
		err = fmt.Errorf("core: unknown command '%s' passed to modify", s.Command)
		return jsonStatusError(err)
	}

	if err != nil {
		return jsonStatusError(err)
	}

	return jsonStatusOk()
}

// Owners processes a owners request.
func Owners(jsonIn []byte) ([]byte, error) {
	var s OwnersRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.owners failed: size=%d %v", len(s.Data), err)
		} else {
			log.Printf("core.owners success: size=%d", len(s.Data))
		}
	}()

	err = json.Unmarshal(jsonIn, &s)
	if err != nil {
		return jsonStatusError(err)
	}

	names, err := crypt.GetOwners(s.Data)
	if err != nil {
		return jsonStatusError(err)
	}

	return json.Marshal(OwnersData{Status: "ok", Owners: names})
}

// Export returns a backed up vault.
func Export(jsonIn []byte) ([]byte, error) {
	var s ExportRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.export failed: user=%s %v", s.Name, err)
		} else {
			log.Printf("core.export success: user=%s", s.Name)
		}
	}()

	err = json.Unmarshal(jsonIn, &s)
	if err != nil {
		return jsonStatusError(err)
	}

	err = validateUser(s.Name, s.Password, true)
	if err != nil {
		return jsonStatusError(err)
	}

	out, err := json.Marshal(records)
	if err != nil {
		return jsonStatusError(err)
	}

	return jsonResponse(out)
}

// Order a Request delegates from other users
func Order(jsonIn []byte) (out []byte, err error) {
	var o OrderRequest

	defer func() {
		if err != nil {
			log.Printf("core.order failed: user=%s %v", o.Name, err)
		} else {
			log.Printf("core.order success: user=%s", o.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &o); err != nil {
		return jsonStatusError(err)
	}

	if err := validateUser(o.Name, o.Password, false); err != nil {
		return jsonStatusError(err)
	}

	owners, err := crypt.GetOwners(o.Data)
	if err != nil {
		errors.New("Unable to find the ciphertext's owners.")
		return
	}
	// If this is a duplicate order then do nothing
	orderNum := order.GenerateNum(o.Name, o.Label)
	if _, dupe := orderer.Orders[orderNum]; dupe {
		errors.New("An order for delegations already exists")
		return
	}
	cache.Refresh()
	// Figure out the number of delegates already, for the case
	// where someone asks for delegates when they are already
	// half delegated
	contacts := crypt.GetContacts(owners)
	go orderer.Notifier.Notify(contacts, o.Label, o.Name, order.NewOrder)

	numDelegated := cache.DelegateStatus(o.Name, o.Label, owners)
	order := order.CreateOrder(o.Name,
		o.Label,
		orderNum,
		contacts,
		numDelegated)
	orderer.Orders[orderNum] = order
	out, err = json.Marshal(order)
	if err != nil {
		return jsonStatusError(err)
	}
	return jsonResponse(out)
}

// OrdersOut will provide a list of current outstanding
// orders to admins who may be looking for someone to provide
// delegates to.
func OrdersOut(jsonIn []byte) (out []byte, err error) {
	var o OrderOutstandingRequest

	defer func() {
		if err != nil {
			log.Printf("core.ordersout failed: user=%s %v", o.Name, err)
		} else {
			log.Printf("core.ordersout success: user=%s", o.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &o); err != nil {
		return jsonStatusError(err)
	}

	if err := validateUser(o.Name, o.Password, false); err != nil {
		return jsonStatusError(err)
	}

	out, err = json.Marshal(orderer.Orders)
	if err != nil {
		return jsonStatusError(err)
	}
	return jsonResponse(out)
}

// OrderInfo is used to retrieve information about a particular
// order number, passed in by a client.
func OrderInfo(jsonIn []byte) (out []byte, err error) {
	var o OrderInfoRequest

	defer func() {
		if err != nil {
			log.Printf("core.order failed: user=%s %v", o.Name, err)
		} else {
			log.Printf("core.order success: user=%s", o.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &o); err != nil {
		return jsonStatusError(err)
	}

	if err := validateUser(o.Name, o.Password, false); err != nil {
		return jsonStatusError(err)
	}

	if ord, ok := orderer.Orders[o.OrderNum]; ok {
		out, err = json.Marshal(ord)
		if err != nil {
			return jsonStatusError(err)
		}
	}
	return jsonResponse(out)
}
