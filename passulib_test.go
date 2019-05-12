package passulib_test

import (
	"errors"
	"github.com/guregu/null"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/winded/passu-lib"
	"regexp"
)

var (
	lowerRegex   *regexp.Regexp
	upperRegex   *regexp.Regexp
	numberRegex  *regexp.Regexp
	specialRegex *regexp.Regexp
)

func init() {
	lowerRegex = regexp.MustCompile(`[a-z]`)
	upperRegex = regexp.MustCompile(`[A-Z]`)
	numberRegex = regexp.MustCompile(`[0-9]`)
	specialRegex = regexp.MustCompile(`[\+\-\=\/\\]`)
}

var _ = Describe("PasswordDatabase", func() {
	Context("Default policy", func() {
		It("should update default policy", func() {
			pwInput := "testpassword"
			db := passulib.NewPasswordDatabase(pwInput)

			db.SetDefaultPolicy(passulib.PasswordPolicy{
				Length:       null.IntFrom(16),
				UseLowercase: null.BoolFrom(false),
				UseUppercase: null.BoolFrom(true),
				UseNumbers:   null.BoolFrom(true),
				UseSpecial:   null.BoolFrom(true),
			})

			policy := db.GetDefaultPolicy()
			Expect(policy.Length).To(Equal(null.IntFrom(16)))
			Expect(policy.UseLowercase).To(Equal(null.BoolFrom(false)))
			Expect(policy.UseUppercase).To(Equal(null.BoolFrom(true)))
			Expect(policy.UseNumbers).To(Equal(null.BoolFrom(true)))
			Expect(policy.UseSpecial).To(Equal(null.BoolFrom(true)))
		})
	})

	Context("Database encryption and decryption", func() {
		It("should encrypt and decrypt the database successfully", func() {
			pwInput := "testpassword"

			db := passulib.NewPasswordDatabase(pwInput)
			err := db.AddEntry(passulib.PasswordEntry{
				"test",
				"mypassword",
				"description",
				passulib.PasswordPolicy{},
			})
			if err != nil {
				panic(err)
			}

			encrypted := db.Save()

			decrypted, err := passulib.PasswordDatabaseFromData(encrypted, pwInput)
			if err != nil {
				panic(err)
			}
			entry, idx := decrypted.GetEntry("test")

			Expect(idx).ToNot(Equal(-1))
			Expect(entry.Name).To(Equal("test"))
			Expect(entry.Password).To(Equal("mypassword"))
			Expect(entry.Description).To(Equal("description"))
		})
		It("should decrypt and re-encrypt with another password successfully", func() {
			pwInput := "testpassword"
			pwInput2 := "anotherpassword"

			db := passulib.NewPasswordDatabase(pwInput)
			db.AddEntry(passulib.PasswordEntry{
				"test",
				"mypassword",
				"description",
				passulib.PasswordPolicy{},
			})

			encrypted := db.Save()

			decrypted, err := passulib.PasswordDatabaseFromData(encrypted, pwInput)
			if err != nil {
				panic(err)
			}
			decrypted.SetPassword(pwInput2)
			encrypted = decrypted.Save()
			decrypted, err = passulib.PasswordDatabaseFromData(encrypted, pwInput2)
			if err != nil {
				panic(err)
			}

			entry, idx := decrypted.GetEntry("test")

			Expect(idx).ToNot(Equal(-1))
			Expect(entry.Name).To(Equal("test"))
			Expect(entry.Password).To(Equal("mypassword"))
			Expect(entry.Description).To(Equal("description"))
		})
	})

	Context("Add/Edit/Delete entries", func() {
		It("should successfully add an entry", func() {
			pwInput := "testpassword"

			db := passulib.NewPasswordDatabase(pwInput)
			err := db.AddEntry(passulib.PasswordEntry{
				"test",
				"its a password134125+-++\\/",
				"description",
				passulib.PasswordPolicy{},
			})
			if err != nil {
				panic(err)
			}

			entry, idx := db.GetEntry("test")

			Expect(idx).ToNot(Equal(-1))
			Expect(entry.Password).To(Equal("its a password134125+-++\\/"))
			Expect(entry.Description).To(Equal("description"))
		})
		It("should fail when entry has invalid name", func() {
			pwInput := "testpassword"

			db := passulib.NewPasswordDatabase(pwInput)
			err := db.AddEntry(passulib.PasswordEntry{
				"test+test space",
				"its a password134125+-++\\/",
				"description",
				passulib.PasswordPolicy{},
			})

			Expect(err).To(Equal(errors.New("Name must only contain alphabetic characters, numbers and dashes")))
		})
		It("should fail when duplicate entry is added", func() {
			pwInput := "testpassword"

			db := passulib.NewPasswordDatabase(pwInput)
			err := db.AddEntry(passulib.PasswordEntry{
				"test",
				"its a password134125+-++\\/",
				"description",
				passulib.PasswordPolicy{},
			})
			if err != nil {
				panic(err)
			}

			err = db.AddEntry(passulib.PasswordEntry{
				"test",
				"its a password134125+-++\\/",
				"description",
				passulib.PasswordPolicy{},
			})

			Expect(err).To(Equal(errors.New("Entry \"test\" already exists.")))
		})
		It("should successfully edit an entry", func() {
			pwInput := "testpassword"

			db := passulib.NewPasswordDatabase(pwInput)
			err := db.AddEntry(passulib.PasswordEntry{
				"test",
				"its a password134125+-++\\/",
				"description",
				passulib.PasswordPolicy{},
			})
			if err != nil {
				panic(err)
			}

			entry, idx := db.GetEntry("test")

			Expect(idx).ToNot(Equal(-1))
			Expect(entry.Password).To(Equal("its a password134125+-++\\/"))
			Expect(entry.Description).To(Equal("description"))

			err = db.UpdateEntry("test", passulib.PasswordEntry{
				"test1",
				"newpassword",
				"another description",
				passulib.PasswordPolicy{},
			})
			entry, idx = db.GetEntry("test1")

			Expect(idx).ToNot(Equal(-1))
			Expect(entry.Password).To(Equal("newpassword"))
			Expect(entry.Description).To(Equal("another description"))
		})
		It("should successfully delete an entry", func() {
			pwInput := "testpassword"

			db := passulib.NewPasswordDatabase(pwInput)
			err := db.AddEntry(passulib.PasswordEntry{
				"test",
				"its a password134125+-++\\/",
				"description",
				passulib.PasswordPolicy{},
			})
			if err != nil {
				panic(err)
			}

			entry, idx := db.GetEntry("test")

			Expect(idx).ToNot(Equal(-1))
			Expect(entry.Password).To(Equal("its a password134125+-++\\/"))
			Expect(entry.Description).To(Equal("description"))

			_, err = db.RemoveEntry("test")
			if err != nil {
				panic(err)
			}
			_, idx = db.GetEntry("test")

			Expect(idx).To(Equal(-1))
		})
	})

	Context("Password generation", func() {
		It("should generate password with default password policy", func() {
			pwInput := "testpassword"

			db := passulib.NewPasswordDatabase(pwInput)
			err := db.AddEntry(passulib.PasswordEntry{
				"test",
				"",
				"description",
				passulib.PasswordPolicy{},
			})
			if err != nil {
				panic(err)
			}
			entry, err := db.GeneratePassword("test")
			if err != nil {
				panic(err)
			}

			Expect(len(entry.Password)).To(Equal(32))
			Expect(lowerRegex.MatchString(entry.Password)).To(Equal(true))
			Expect(upperRegex.MatchString(entry.Password)).To(Equal(true))
			Expect(numberRegex.MatchString(entry.Password)).To(Equal(true))
			Expect(specialRegex.MatchString(entry.Password)).To(Equal(true))
		})
		It("should generate password with updated default password policy", func() {
			pwInput := "testpassword"

			db := passulib.NewPasswordDatabase(pwInput)
			db.SetDefaultPolicy(passulib.PasswordPolicy{
				null.IntFrom(20),
				null.BoolFrom(true),
				null.BoolFrom(true),
				null.BoolFrom(true),
				null.BoolFrom(false),
			})
			err := db.AddEntry(passulib.PasswordEntry{
				"test",
				"",
				"description",
				passulib.PasswordPolicy{},
			})
			if err != nil {
				panic(err)
			}
			entry, err := db.GeneratePassword("test")
			if err != nil {
				panic(err)
			}

			Expect(len(entry.Password)).To(Equal(20))
			Expect(lowerRegex.MatchString(entry.Password)).To(Equal(true))
			Expect(upperRegex.MatchString(entry.Password)).To(Equal(true))
			Expect(numberRegex.MatchString(entry.Password)).To(Equal(true))
			Expect(specialRegex.MatchString(entry.Password)).To(Equal(false))
		})
		It("should generate password with specified password policy", func() {
			pwInput := "testpassword"

			db := passulib.NewPasswordDatabase(pwInput)
			err := db.AddEntry(passulib.PasswordEntry{
				"test",
				"",
				"description",
				passulib.PasswordPolicy{
					null.IntFrom(16),
					null.BoolFrom(true),
					null.BoolFrom(false),
					null.BoolFrom(true),
					null.BoolFrom(false),
				},
			})
			if err != nil {
				panic(err)
			}
			entry, err := db.GeneratePassword("test")
			if err != nil {
				panic(err)
			}

			Expect(len(entry.Password)).To(Equal(16))
			Expect(lowerRegex.MatchString(entry.Password)).To(Equal(true))
			Expect(upperRegex.MatchString(entry.Password)).To(Equal(false))
			Expect(numberRegex.MatchString(entry.Password)).To(Equal(true))
			Expect(specialRegex.MatchString(entry.Password)).To(Equal(false))
		})
		It("should generate password with partially default password policy", func() {
			pwInput := "testpassword"

			db := passulib.NewPasswordDatabase(pwInput)
			err := db.AddEntry(passulib.PasswordEntry{
				"test",
				"",
				"description",
				passulib.PasswordPolicy{
					null.IntFrom(8),
					null.BoolFrom(false),
					null.NewBool(false, false),
					null.NewBool(false, false),
					null.NewBool(false, false),
				},
			})
			if err != nil {
				panic(err)
			}
			entry, err := db.GeneratePassword("test")
			if err != nil {
				panic(err)
			}

			Expect(len(entry.Password)).To(Equal(8))
			Expect(lowerRegex.MatchString(entry.Password)).To(Equal(false))
			Expect(upperRegex.MatchString(entry.Password)).To(Equal(true))
			Expect(numberRegex.MatchString(entry.Password)).To(Equal(true))
			Expect(specialRegex.MatchString(entry.Password)).To(Equal(true))
		})
	})
})
