package order

import (
//	"fmt"
	"crypto/sha256"
//	"errors"
	"encoding/hex"
//	"net/smtp"
)
type Order struct {
	Name		string
	Num		string

	Delegated	int
	ToDelegate	int
	AdminsDelegated	[]string
	Admins		[]AdminContact
	Label		string
}
type AdminContact struct {
	Name	string
	Email	string
}

type Orders map[string]Order
// Orders represents a mapping of Order IDs to Orders. This structure
// is useful for looking up information about individual Orders and
// whether or not an order has been fulfilled. Orders that have been
// fulfilled will removed from the structure.

func CreateOrder(name string, labels string, orderNum string, contacts []AdminContact, numDelegated int) (ord Order) {
	ord.Name      = name
	ord.Num       = orderNum
	ord.Label     = labels
	ord.Admins    = contacts
	ord.Delegated = numDelegated
	return
}

func GenerateNum(name string, label string) (num string) {

	hasher := sha256.New()
	hasher.Write([]byte(name+label))
	hexNum := hasher.Sum(nil)

	return hex.EncodeToString(hexNum)

}
func GenerateNums(names, labels []string) (nums []string) {
	for _, name := range names {
		for _, label := range labels{
			nums = append(nums, GenerateNum(name, label))
		}
	}
	return
}
