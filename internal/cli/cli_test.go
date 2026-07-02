package cli

import (
	"testing"
)

func TestRunHelp(t *testing.T) {
	// just ensure does not panic on known paths
	err := Run([]string{"help"})
	if err != nil {
		t.Log("help returned err (ok for usage)")
	}
}

func TestUnknown(t *testing.T) {
	err := Run([]string{"bogus-cmd"})
	if err == nil {
		t.Error("expected error on unknown")
	}
}
