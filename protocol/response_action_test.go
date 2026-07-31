package protocol

import (
	"errors"
	"testing"
	"time"
)

func TestResponseActionNormalizeAcceptsDeliveryStates(t *testing.T) {
	for _, status := range []string{ResponseActionPending, ResponseActionDelivered} {
		action := ResponseAction{
			ID:          1,
			ActionType:  ActionTriggerInventory,
			AgentID:     "agent-1",
			Status:      status,
			RequestedAt: time.Now().UTC(),
		}
		if err := action.Normalize(); err != nil {
			t.Fatalf("expected %q status to be valid: %v", status, err)
		}
	}
}

func TestResponseActionNormalizeRejectsUnknownStatus(t *testing.T) {
	action := ResponseAction{
		ID:          1,
		ActionType:  ActionTriggerInventory,
		AgentID:     "agent-1",
		Status:      "executing",
		RequestedAt: time.Now().UTC(),
	}
	err := action.Normalize()
	if !errors.Is(err, ErrInvalidResponseAction) {
		t.Fatalf("expected invalid response action error, got %v", err)
	}
}
