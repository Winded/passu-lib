package passulib_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestPassuLib(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "PassuLib Suite")
}
