package passulib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/guregu/null"
	"golang.org/x/crypto/scrypt"
	"io"
	"math"
	"math/big"
	"regexp"
)

const SCRYPT_N = 32768
const SCRYPT_R = 8
const SCRYPT_P = 1

const SIGNATURE = "PASSU"
const SCRYPT_SALT_LEN = 32
const AES_CBC_KEYLEN = 32
const AES_CBC_IVLEN = 16

var entryNameRegexp *regexp.Regexp

type Error struct {
	Message string
}

func (this Error) Error() string {
	return fmt.Sprintf("Passu Error: %q", this.Message)
}

type PasswordPolicy struct {
	Length       null.Int
	UseLowercase null.Bool
	UseUppercase null.Bool
	UseNumbers   null.Bool
	UseSpecial   null.Bool
}

type PasswordEntry struct {
	Name           string
	Password       string
	Description    string
	PolicyOverride PasswordPolicy
}

type PasswordData struct {
	PasswordPolicy PasswordPolicy
	Entries        []PasswordEntry
}

type PasswordDatabase struct {
	Modified     bool
	passwordHash []byte
	passwordSalt []byte
	data         PasswordData
}

func init() {
	entryNameRegexp = regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)
}

func updatePolicy(original, update PasswordPolicy) PasswordPolicy {
	new := original
	if update.Length.Valid {
		new.Length = update.Length
	}
	if update.UseLowercase.Valid {
		new.UseLowercase = update.UseLowercase
	}
	if update.UseUppercase.Valid {
		new.UseUppercase = update.UseUppercase
	}
	if update.UseNumbers.Valid {
		new.UseNumbers = update.UseNumbers
	}
	if update.UseSpecial.Valid {
		new.UseSpecial = update.UseSpecial
	}
	return new
}

func shuffleBytes(bytes []byte) []byte {
	var a = make([]byte, len(bytes))
	copy(a, bytes)
	n := len(a)

	for i := n - 1; i > 0; i-- {
		jbmax := big.NewInt(int64(i + 1))
		jb, _ := rand.Int(rand.Reader, jbmax)
		j := jb.Int64()
		tmp := a[i]
		a[i] = a[j]
		a[j] = tmp
	}

	return a
}

func addZeroPad(bytes []byte, blockSize int) []byte {
	r := bytes

	for len(r)%blockSize != 0 {
		r = append(r, 0)
	}

	return r
}

func removeZeroPad(bytes []byte) []byte {
	r := bytes

	for i := len(bytes) - 1; i >= 0; i-- {
		if bytes[i] != 0 {
			r = bytes[:(i + 1)]
			break
		}
	}

	return r
}

// PasswordDatabaseFromData decrypts and deserializes a password database
// from given data with the raw, non-hashed inputPassword
func PasswordDatabaseFromData(data []byte, inputPassword string) (*PasswordDatabase, error) {
	var (
		signature       []byte
		ivByteLength    byte
		iv              []byte
		saltLen         byte
		passwordSalt    []byte
		edataByteLength int32
		edata           []byte
		err             error
		passwordHash    []byte
	)

	bytes := bytes.NewBuffer(data)

	signature = bytes.Next(len(SIGNATURE))
	if string(signature) != SIGNATURE {
		return nil, errors.New("File is not a password file")
	}

	binary.Read(bytes, binary.BigEndian, &ivByteLength)
	iv = bytes.Next(int(ivByteLength))

	binary.Read(bytes, binary.BigEndian, &saltLen)
	passwordSalt = bytes.Next(int(saltLen))

	binary.Read(bytes, binary.BigEndian, &edataByteLength)

	edata = bytes.Next(int(edataByteLength))

	passwordHash, err = scrypt.Key([]byte(inputPassword), passwordSalt, SCRYPT_N, SCRYPT_R, SCRYPT_P, AES_CBC_KEYLEN)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(passwordHash)
	if err != nil {
		return nil, err
	}
	decrypter := cipher.NewCBCDecrypter(c, iv)

	sdata := make([]byte, len(edata))
	decrypter.CryptBlocks(sdata, edata)
	sdata = removeZeroPad(sdata)

	var pwData PasswordData
	err = json.Unmarshal(sdata, &pwData)

	if err != nil {
		return nil, err
	}

	db := NewPasswordDatabase(inputPassword)
	db.data = pwData
	db.Modified = false

	return db, nil
}

func NewPasswordDatabase(inputPassword string) *PasswordDatabase {
	this := &PasswordDatabase{}

	this.SetPassword(inputPassword)

	this.data = PasswordData{
		PasswordPolicy: PasswordPolicy{
			Length:       null.IntFrom(32),
			UseLowercase: null.BoolFrom(true),
			UseUppercase: null.BoolFrom(true),
			UseNumbers:   null.BoolFrom(true),
			UseSpecial:   null.BoolFrom(true),
		},
		Entries: make([]PasswordEntry, 0),
	}

	this.Modified = false

	return this
}

func (this *PasswordDatabase) GetDefaultPolicy() PasswordPolicy {
	return this.data.PasswordPolicy
}

func (this *PasswordDatabase) SetDefaultPolicy(value PasswordPolicy) error {
	if value.Length.Valid && value.Length.Int64 < 0 {
		return Error{"Password policy length can't be 0 or lower"}
	}

	this.data.PasswordPolicy = updatePolicy(this.data.PasswordPolicy, value)

	this.Modified = true
	return nil
}

// SetPassword sets the given raw, non-hashed value as the new master password of the database.
// It generates a random salt and hashes the password with that salt.
func (this *PasswordDatabase) SetPassword(value string) {
	var err error
	this.passwordSalt = make([]byte, SCRYPT_SALT_LEN)
	io.ReadFull(rand.Reader, this.passwordSalt)
	this.passwordHash, err = scrypt.Key([]byte(value), this.passwordSalt, SCRYPT_N, SCRYPT_R, SCRYPT_P, AES_CBC_KEYLEN)
	if err != nil {
		panic(err)
	}
	this.Modified = true
}

// GeneratePassword generates a new password for the password entry found with entryName.
func (this *PasswordDatabase) GeneratePassword(entryName string) (PasswordEntry, error) {
	entry, entryIdx := this.GetEntry(entryName)
	if entryIdx == -1 {
		return PasswordEntry{}, Error{fmt.Sprintf("Entry %q not found.", entryName)}
	}

	policy := updatePolicy(this.data.PasswordPolicy, entry.PolicyOverride)

	sets := make([]string, 0, 4)
	if policy.UseLowercase.Valid && policy.UseLowercase.Bool {
		sets = append(sets, "abcdefghijklmnopqrstuvwxyz")
	}
	if policy.UseUppercase.Valid && policy.UseUppercase.Bool {
		sets = append(sets, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	}
	if policy.UseNumbers.Valid && policy.UseNumbers.Bool {
		sets = append(sets, "0123456789")
	}
	if policy.UseSpecial.Valid && policy.UseSpecial.Bool {
		sets = append(sets, "+-=/\\")
	}

	if len(sets) == 0 {
		return PasswordEntry{}, Error{"Entry policy is invalid. No character sets are allowed."}
	}

	charactersPerSet := int(math.Ceil(float64(policy.Length.Int64) / float64(len(sets))))

	password := make([]byte, 0, policy.Length.Int64)
	for _, set := range sets {
		setlen := big.NewInt(int64(len(set)))
		for i := 0; i < charactersPerSet; i++ {
			c, _ := rand.Int(rand.Reader, setlen)
			password = append(password, set[c.Int64()])
		}
	}
	password = shuffleBytes(password)
	password = password[:policy.Length.Int64]

	entry.Password = string(password)
	err := this.UpdateEntry(entry.Name, entry)
	if err != nil {
		panic(err)
	}

	this.Modified = true
	return entry, nil
}

func (this *PasswordDatabase) AllEntries() []PasswordEntry {
	return this.data.Entries
}

func (this *PasswordDatabase) FindEntries(startsWith string) []PasswordEntry {
	entries := make([]PasswordEntry, 0)
	for _, entry := range this.data.Entries {
		if len(entry.Name) >= len(startsWith) && entry.Name[:len(startsWith)] == startsWith {
			entries = append(entries, entry)
		}
	}
	return entries
}

func (this *PasswordDatabase) GetEntry(name string) (PasswordEntry, int) {
	for index, entry := range this.data.Entries {
		if entry.Name == name {
			return entry, index
		}
	}
	return PasswordEntry{}, -1
}

func (this *PasswordDatabase) AddEntry(entry PasswordEntry) error {
	if !entryNameRegexp.MatchString(entry.Name) {
		return Error{"Name must only contain alphabetic characters, numbers and dashes"}
	}
	_, existingEntryIndex := this.GetEntry(entry.Name)
	if existingEntryIndex != -1 {
		return Error{fmt.Sprintf("Entry %q already exists.", entry.Name)}
	}

	this.data.Entries = append(this.data.Entries, entry)
	this.Modified = true
	return nil
}

func (this *PasswordDatabase) UpdateEntry(name string, updatedEntry PasswordEntry) error {
	_, index := this.GetEntry(name)
	if index == -1 {
		return Error{fmt.Sprintf("Entry %q not found.", name)}
	}

	if !entryNameRegexp.MatchString(updatedEntry.Name) {
		return Error{"Name must only contain alphabetic characters, numbers and dashes"}
	}

	_, existingEntryIndex := this.GetEntry(updatedEntry.Name)
	if name != updatedEntry.Name && existingEntryIndex != -1 {
		return Error{fmt.Sprintf("Entry %q already exists.", updatedEntry.Name)}
	}

	this.data.Entries[index] = updatedEntry
	this.Modified = true
	return nil
}

func (this *PasswordDatabase) RemoveEntry(name string) (PasswordEntry, error) {
	entry, index := this.GetEntry(name)
	if index == -1 {
		return PasswordEntry{}, Error{fmt.Sprintf("Entry %q not found.", name)}
	}

	this.data.Entries = append(this.data.Entries[:index], this.data.Entries[(index+1):]...)
	this.Modified = true
	return entry, nil
}

// Save serializes and encrypts the password database, returning the encrypted data
func (this *PasswordDatabase) Save() []byte {
	ivLen := byte(AES_CBC_IVLEN)
	iv := make([]byte, ivLen)
	io.ReadFull(rand.Reader, iv)
	c, err := aes.NewCipher(this.passwordHash)
	if err != nil {
		panic(err)
	}
	crypter := cipher.NewCBCEncrypter(c, iv)

	saltLen := byte(len(this.passwordSalt))

	sdata, err := json.Marshal(this.data)
	if err != nil {
		panic(err)
	}
	sdata = addZeroPad(sdata, 32)
	edata := make([]byte, len(sdata))
	crypter.CryptBlocks(edata, sdata)
	edataLen := int32(len(edata))

	buf := new(bytes.Buffer)

	buf.Write([]byte(SIGNATURE))

	binary.Write(buf, binary.BigEndian, &ivLen)
	buf.Write(iv)

	binary.Write(buf, binary.BigEndian, &saltLen)
	buf.Write(this.passwordSalt)

	binary.Write(buf, binary.BigEndian, &edataLen)
	buf.Write(edata)

	this.Modified = false
	return buf.Bytes()
}
