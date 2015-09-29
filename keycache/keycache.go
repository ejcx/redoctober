// Package keycache provides the ability to hold active keys in memory
// for the Red October server.
//
// Copyright (c) 2013 CloudFlare, Inc.

package keycache

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"errors"
	"log"
	"time"

	"github.com/cloudflare/redoctober/ecdh"
	"github.com/cloudflare/redoctober/passvault"
)

// Usage holds the permissions of a delegated permission
type Usage struct {
	Uses     int       // Number of uses delegated
	Labels   []string  // File labels allowed to decrypt
	Users    []string  // Set of users allows to decrypt
	Expiry   time.Time // Expiration of usage
	OrderNum string    // OrderNumber associated with delegation
}

// ActiveUser holds the information about an actively delegated key.
type ActiveUser struct {
	Usage
	Admin  bool
	Type   string
	rsaKey rsa.PrivateKey
	eccKey *ecdsa.PrivateKey
}

type Cache struct {
	UserKeys map[string]ActiveUser // Decrypted keys in memory, indexed by name.
}

// matchesLabel returns true if this usage applies the user and label
// an empty array of Users indicates that all users are valid
func (usage Usage) matchesLabel(labels []string) bool {
	// if asset has no labels always match
	if len(labels) == 0 {
		return true
	}

	for _, validLabel := range usage.Labels {
		for _, label := range labels {
			if label == validLabel {
				return true
			}
		}
	}
	return false
}

// matches returns true if this usage applies the user and label
// an empty array of Users indicates that all users are valid
func (usage Usage) matches(user string, labels []string) bool {
	if !usage.matchesLabel(labels) {
		return false
	}
	// if usage lists no users, always match
	if len(usage.Users) == 0 {
		return true
	}
	for _, validUser := range usage.Users {
		if user == validUser {
			return true
		}
	}
	return false
}

func NewCache() Cache {
	return Cache{make(map[string]ActiveUser)}
}

// setUser takes an ActiveUser and adds it to the cache.
func (cache *Cache) setUser(in ActiveUser, name string) {
	cache.UserKeys[name] = in
}

// Valid returns true if matching active user is present.
func (cache *Cache) Valid(name, user string, labels []string) (present bool) {
	key, present := cache.UserKeys[name]
	if present {
		if key.Usage.matches(user, labels) {
			return true
		} else {
			present = false
		}
	}

	return
}

// MatchUser returns the matching active user if present
// and a boolean to indicate its presence.
func (cache *Cache) MatchUser(name, user string, labels []string) (out ActiveUser, present bool) {
	key, present := cache.UserKeys[name]
	if present {
		if key.Usage.matches(user, labels) {
			return key, true
		} else {
			present = false
		}
	}

	return
}

// useKey decrements the counter on an active key
// for decryption or symmetric encryption
func (cache *Cache) useKey(name, user string, labels []string) {
	if val, present := cache.MatchUser(name, user, labels); present {
		val.Usage.Uses -= 1
		cache.setUser(val, name)
	}
}

// GetSummary returns the list of active user keys.
func (cache *Cache) GetSummary() map[string]ActiveUser {
	return cache.UserKeys
}

// FlushCache removes all delegated keys.
func (cache *Cache) FlushCache() {
	for name := range cache.UserKeys {
		delete(cache.UserKeys, name)
	}
}

// Refresh purges all expired or used up keys.
func (cache *Cache) Refresh() {
	for name, active := range cache.UserKeys {
		isOrderUp := false
		isUsedUp := false
		if len(active.Usage.OrderNum) != 0 {
			if time.Now().After(active.Usage.Expiry) {
				isOrderUp = true
			}
		} else {
			isUsedUp = active.Usage.Uses <= 0
		}
		if active.Usage.Expiry.Before(time.Now()) || (isUsedUp || isOrderUp) {
			log.Println("Record expired", name, active.Usage.Users, active.Usage.Labels, active.Usage.Expiry)
			delete(cache.UserKeys, name)
		}
	}
}

// AddKeyFromRecord decrypts a key for a given record and adds it to the cache.
func (cache *Cache) AddKeyFromRecord(record passvault.PasswordRecord, name, password string, users, labels []string, uses int, durationString string, orderNum string) (err error) {
	var current ActiveUser

	cache.Refresh()

	// compute exipiration
	duration, err := time.ParseDuration(durationString)
	if err != nil {
		return
	}
	current.Usage.Uses = uses
	current.Usage.Expiry = time.Now().Add(duration)
	current.Usage.Users = users
	current.Usage.Labels = labels
	current.Usage.OrderNum = orderNum

	// get decryption keys
	switch record.Type {
	case passvault.RSARecord:
		current.rsaKey, err = record.GetKeyRSA(password)
	case passvault.ECCRecord:
		current.eccKey, err = record.GetKeyECC(password)
	default:
		err = errors.New("Unknown record type")
	}

	if err != nil {
		return
	}

	// set types
	current.Type = record.Type
	current.Admin = record.Admin

	// add current to map (overwriting previous for this name)
	cache.setUser(current, name)

	return
}

// DecryptKey decrypts a 16 byte key using the key corresponding to the name parameter
// For RSA and EC keys, the cached RSA/EC key is used to decrypt
// the pubEncryptedKey which is then used to decrypt the input
// buffer.
func (cache *Cache) DecryptKey(in []byte, name, user string, labels []string, pubEncryptedKey []byte) (out []byte, err error) {
	cache.Refresh()

	decryptKey, ok := cache.MatchUser(name, user, labels)
	if !ok {
		return nil, errors.New("Key not delegated")
	}

	var aesKey []byte

	// pick the aesKey to use for decryption
	switch decryptKey.Type {
	case passvault.RSARecord:
		// extract the aes key from the pubEncryptedKey
		aesKey, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, &decryptKey.rsaKey, pubEncryptedKey, nil)
		if err != nil {
			return out, err
		}
	case passvault.ECCRecord:
		// extract the aes key from the pubEncryptedKey
		aesKey, err = ecdh.Decrypt(decryptKey.eccKey, pubEncryptedKey)

		if err != nil {
			return out, err
		}
	default:
		return nil, errors.New("unknown type")
	}

	// decrypt
	aesSession, err := aes.NewCipher(aesKey)
	if err != nil {
		return out, err
	}
	out = make([]byte, 16)
	aesSession.Decrypt(out, in)

	cache.useKey(name, user, labels)

	return
}

// DecryptShares decrypts an array of 16 byte shares using the key corresponding
// to the name parameter.
func (cache *Cache) DecryptShares(in [][]byte, name, user string, labels []string, pubEncryptedKey []byte) (out [][]byte, err error) {
	cache.Refresh()

	decryptKey, ok := cache.MatchUser(name, user, labels)
	if !ok {
		return nil, errors.New("Key not delegated")
	}

	var aesKey []byte

	// pick the aesKey to use for decryption
	switch decryptKey.Type {
	case passvault.RSARecord:
		// extract the aes key from the pubEncryptedKey
		aesKey, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, &decryptKey.rsaKey, pubEncryptedKey, nil)
		if err != nil {
			return
		}
	case passvault.ECCRecord:
		// extract the aes key from the pubEncryptedKey
		aesKey, err = ecdh.Decrypt(decryptKey.eccKey, pubEncryptedKey)

		if err != nil {
			return
		}
	default:
		return nil, errors.New("unknown type")
	}

	// decrypt
	aesSession, err := aes.NewCipher(aesKey)
	if err != nil {
		return
	}

	for _, encShare := range in {
		tmp := make([]byte, 16)
		aesSession.Decrypt(tmp, encShare)

		out = append(out, tmp)
	}

	cache.useKey(name, user, labels)

	return
}
func (cache *Cache) DelegateStatus(name string, label string, admins []string) (hasDelegated int) {
	uk := cache.UserKeys
	//Iterate over the admins of the ciphertext. Incredibly ugly but I don't
	//  see a better way to find this information.
	delegations := 0
	for _, admin := range admins {
		use := uk[admin].Usage
		labelFound := false
		nameFound := false
		//Make sure the user who wants access is found
		users := use.Users
		for _, user := range users {
			if user == name {
				nameFound = true
			}
		}
		for _, l := range use.Labels {
			if l == label {
				labelFound = true
			}
		}
		if labelFound && nameFound {
			delegations++
		}
	}
	return delegations
}
