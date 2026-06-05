package seam_test

import (
	"context"
	"testing"

	"github.com/tiagosilva07/invoke-guard/internal/seam"
)

type fakeEco struct{}

func (fakeEco) Name() string                                              { return "npm" }
func (fakeEco) ValidateName(string) error                                 { return nil }
func (fakeEco) Exists(context.Context, string, string) (bool, error)      { return true, nil }
func (fakeEco) Metadata(context.Context, string) (seam.Metadata, error)   { return seam.Metadata{}, nil }
func (fakeEco) PopularList() []string                                     { return []string{"request"} }
func (fakeEco) Install(context.Context, []string, seam.InstallOpts) error { return nil }

func TestEcosystemSatisfiable(t *testing.T) {
	var _ seam.Ecosystem = fakeEco{} // compile-time assertion
}
