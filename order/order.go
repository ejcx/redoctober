package order

import (
	"crypto/sha256"
	//	"errors"
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"net/smtp"
	"text/template"
)

var NewOrder = `
	Hello,
	{{.From}} has requested delegates for {{.Label}}
`
var OrderFulfilled = `
	Hello,
	{{.From}}'s request for has been {{.Label}} fulfilled
`

type Order struct {
	Name string
	Num  string

	Delegated       int
	ToDelegate      int
	AdminsDelegated []string
	Admins          []AdminContact
	Label           string
}
type AdminContact struct {
	Name  string
	Email string
}
type SmtpAuth struct {
	Host, Username, Password string
	Port, Addr, Identity     string
}
type Notifier interface {
	Notify(to, label, name, msg string)
}
type Orderer struct {
	Orders   map[string]Order
	Notifier SmtpAuth
}

// Orders represents a mapping of Order IDs to Orders. This structure
// is useful for looking up information about individual Orders and
// whether or not an order has been fulfilled. Orders that have been
// fulfilled will removed from the structure.

func CreateOrder(name string, labels string, orderNum string, contacts []AdminContact, numDelegated int) (ord Order) {
	ord.Name = name
	ord.Num = orderNum
	ord.Label = labels
	ord.Admins = contacts
	ord.Delegated = numDelegated
	return
}

func GenerateNum(name string, label string) (num string) {

	hasher := sha256.New()
	hasher.Write([]byte(name + label))
	hexNum := hasher.Sum(nil)
	return hex.EncodeToString(hexNum)

}
func GenerateNums(names, labels []string) (nums []string) {
	for _, name := range names {
		for _, label := range labels {
			nums = append(nums, GenerateNum(name, label))
		}
	}
	return
}
func (o *Orderer) PrepareOrders() {
	o.Orders = make(map[string]Order)
}

func (s *SmtpAuth) Notify(to []AdminContact, label, name, msg string) {
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
	emailLabels := map[string]string{"From": name, "Label": label}

	tmpl.Execute(emailBytes, emailLabels)
	err = smtp.SendMail(fullHost, smtpAuth, s.Username, toEmails, emailBytes.Bytes())
	if err != nil {
		log.Printf("%s", err.Error())
	}
}
