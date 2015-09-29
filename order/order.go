package order

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/smtp"
	"text/template"
	"time"
)

// NewOrder is sent to admins of a ciphertext
// when a new order is created.
var NewOrder = `
	Hello,
	{{.From}} has requested delegates for {{.Label}}. 

	Please use the following order number: {{.Order}}.
`

// OrderFulfilled is sent to admins of a ciphertext
// when a requested ciphertext is decrypted
var OrderFulfilled = `
	Hello,
	{{.From}}'s request for has been {{.Label}} fulfilled.

	The following order number is now fulfilled: {{.Order}}.
`

var OrderLocked = `
	Hello,
	{{.From}} has locked their order for {{.Label}}.

	The corresponding order num was: {{.Order}}.

`

// Order is an individual request for delegates that
// any user can make.
type Order struct {
	Name              string
	Num               string
	TimeRequested     time.Time
	ExpiryTime        time.Time
	DurationRequested time.Duration
	Delegated         int
	ToDelegate        int
	AdminsDelegated   []string
	Admins            []AdminContact
	Label             string
}

// AdminContact essentially couples the name with
// the email address of a user into one type
type AdminContact struct {
	Name  string
	Email string
}

// SMTPAuth contains the information needed
// to create an smtp.PlainAuth.
type SMTPAuth struct {
	Host, Username, Password string
	Port, Addr, Identity     string
}

// Notifier is an interface to provide a standard
// method for notifications over any type of medium.
type Notifier interface {
	Notify(to, label, name, msg string)
}

// Orderer contains a notifier and a order mapping.
type Orderer struct {
	Orders   map[string]Order
	Notifier SMTPAuth
}

// CreateOrder is essentially a factory function for turning
// the information that belongs in an order, into an order type
func CreateOrder(name string, labels string, orderNum string, time time.Time, expiryTime time.Time, duration time.Duration, contacts []AdminContact, numDelegated int) (ord Order) {
	ord.Name = name
	ord.Num = orderNum
	ord.Label = labels
	ord.Admins = contacts
	ord.TimeRequested = time
	ord.ExpiryTime = expiryTime
	ord.DurationRequested = duration
	ord.Delegated = numDelegated
	return
}

// GenerateNum takes a name and a label and and turns it
// into an order number. Currently it is only a SHA256 sum
// of the label and orderer name. This means order numbers
// are static for as long as orders are being placed.
func GenerateNum() (num string) {
	b := make([]byte, 32)
	hasher := sha256.New()
	rand.Read(b)
	hasher.Write(b)
	hexNum := hasher.Sum(nil)
	return hex.EncodeToString(hexNum)
}

// PrepareOrders Create a new map of Orders
func (o *Orderer) PrepareOrders() {
	o.Orders = make(map[string]Order)
}

// Notify sends arbirtrary messages to admins of any label
func (s *SMTPAuth) Notify(to []AdminContact, label, name, orderNum, msg string) {
	toEmails := *new([]string)
	for _, contact := range to {
		if contact.Email != "" {
			toEmails = append(toEmails, contact.Email)
		}
	}
	smtpAuth := smtp.PlainAuth(
		s.Identity,
		s.Username,
		s.Password,
		s.Host)
	fullHost := fmt.Sprintf("%s:%s", s.Host, s.Port)
	emailBytes := new(bytes.Buffer)
	tmpl, err := template.New("NotifyTmpl").Parse(msg)
	if err != nil {
		log.Printf("%s", err.Error())
	}
	emailLabels := map[string]string{"From": name, "Label": label, "Order": orderNum}

	tmpl.Execute(emailBytes, emailLabels)
	err = smtp.SendMail(fullHost, smtpAuth, s.Username, toEmails, emailBytes.Bytes())
	if err != nil {
		log.Printf("%s", err.Error())
	} else {
		log.Printf("Mail Successfully Sent")
	}
}
