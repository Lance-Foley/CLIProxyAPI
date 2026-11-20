package auth

import (
	"context"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func claudeWindowAuth(id, fiveHourUtilization, sevenDayReset string) *Auth {
	return &Auth{
		ID:       id,
		Provider: "claude",
		Quota: QuotaState{
			Signals: map[string]string{
				"Anthropic-Ratelimit-Unified-5h-Utilization": fiveHourUtilization,
				"Anthropic-Ratelimit-Unified-7d-Reset":       sevenDayReset,
			},
		},
	}
}

func TestRoundRobinSelector_PrefersSoonestWeeklyReset(t *testing.T) {
	t.Parallel()

	selector := &RoundRobinSelector{}
	auths := []*Auth{
		claudeWindowAuth("late", "0.40", "5000"),
		claudeWindowAuth("soon", "0.10", "1000"),
		claudeWindowAuth("mid", "0.30", "3000"),
	}

	for i := 0; i < 3; i++ {
		got, errPick := selector.Pick(context.Background(), "claude", "claude-sonnet", cliproxyexecutor.Options{}, auths)
		if errPick != nil {
			t.Fatalf("Pick() #%d error = %v", i, errPick)
		}
		if got == nil || got.ID != "soon" {
			t.Fatalf("Pick() #%d auth = %v, want soon", i, got)
		}
	}
}

func TestRoundRobinSelector_SharesFiveHourRoomBelowSoonestWeeklyReset(t *testing.T) {
	t.Parallel()

	selector := &RoundRobinSelector{}
	auths := []*Auth{
		claudeWindowAuth("soon", "0.80", "1000"),
		claudeWindowAuth("room", "0.20", "9000"),
		claudeWindowAuth("full", "0.90", "8000"),
	}

	want := []string{"room", "soon", "room", "soon"}
	for i, id := range want {
		got, errPick := selector.Pick(context.Background(), "claude", "claude-sonnet", cliproxyexecutor.Options{}, auths)
		if errPick != nil {
			t.Fatalf("Pick() #%d error = %v", i, errPick)
		}
		if got == nil || got.ID != id {
			t.Fatalf("Pick() #%d auth = %v, want %s", i, got, id)
		}
	}
}

func TestRoundRobinSelector_MissingWeeklyResetUsesFullRotation(t *testing.T) {
	t.Parallel()

	selector := &RoundRobinSelector{}
	auths := []*Auth{
		claudeWindowAuth("b", "0.10", "1000"),
		{ID: "a", Provider: "claude"},
	}

	want := []string{"a", "b", "a"}
	for i, id := range want {
		got, errPick := selector.Pick(context.Background(), "claude", "claude-sonnet", cliproxyexecutor.Options{}, auths)
		if errPick != nil {
			t.Fatalf("Pick() #%d error = %v", i, errPick)
		}
		if got == nil || got.ID != id {
			t.Fatalf("Pick() #%d auth = %v, want %s", i, got, id)
		}
	}
}

func TestSessionAffinitySelector_KeepsBindingWhenWeeklyResetPrefersAnotherAccount(t *testing.T) {
	t.Parallel()

	selector := NewSessionAffinitySelector(&RoundRobinSelector{})
	defer selector.Stop()

	boundPayload := []byte(`{"metadata":{"user_id":"user_xxx_account__session_ac980658-63bd-4fb3-97ba-8da64cb1e344"}}`)
	boundOpts := cliproxyexecutor.Options{OriginalRequest: boundPayload}
	plain := []*Auth{
		{ID: "bound", Provider: "claude"},
		{ID: "later", Provider: "claude"},
		{ID: "soon", Provider: "claude"},
	}

	first, errFirst := selector.Pick(context.Background(), "claude", "claude-sonnet", boundOpts, plain)
	if errFirst != nil {
		t.Fatalf("first Pick() error = %v", errFirst)
	}
	if first == nil || first.ID != "bound" {
		t.Fatalf("first Pick() auth = %v, want bound", first)
	}

	signaled := []*Auth{
		claudeWindowAuth("bound", "0.90", "9000"),
		claudeWindowAuth("later", "0.80", "8000"),
		claudeWindowAuth("soon", "0.10", "1000"),
	}
	kept, errKept := selector.Pick(context.Background(), "claude", "claude-sonnet", boundOpts, signaled)
	if errKept != nil {
		t.Fatalf("bound Pick() error = %v", errKept)
	}
	if kept == nil || kept.ID != "bound" {
		t.Fatalf("bound Pick() auth = %v, want bound", kept)
	}

	otherPayload := []byte(`{"metadata":{"user_id":"user_xxx_account__session_bb980658-63bd-4fb3-97ba-8da64cb1e355"}}`)
	otherOpts := cliproxyexecutor.Options{OriginalRequest: otherPayload}
	next, errNext := selector.Pick(context.Background(), "claude", "claude-sonnet", otherOpts, signaled)
	if errNext != nil {
		t.Fatalf("new session Pick() error = %v", errNext)
	}
	if next == nil || next.ID != "soon" {
		t.Fatalf("new session Pick() auth = %v, want soon", next)
	}
}

// weeklyOnlyClaudeAuth mirrors the headers Anthropic sends when an account has no
// 5-hour window: only the 7-day reset and utilization are present.
func weeklyOnlyClaudeAuth(id, sevenDayUtilization, sevenDayReset string) *Auth {
	return &Auth{
		ID:       id,
		Provider: "claude",
		Quota: QuotaState{
			Signals: map[string]string{
				"Anthropic-Ratelimit-Unified-7d-Reset":       sevenDayReset,
				"Anthropic-Ratelimit-Unified-7d-Status":      "allowed",
				"Anthropic-Ratelimit-Unified-7d-Utilization": sevenDayUtilization,
				"Anthropic-Ratelimit-Unified-Reset":          sevenDayReset,
				"Anthropic-Ratelimit-Unified-Status":         "allowed",
			},
		},
	}
}

func TestRoundRobinSelector_PrefersSoonestWeeklyResetWithoutFiveHourSignal(t *testing.T) {
	t.Parallel()

	selector := &RoundRobinSelector{}
	auths := []*Auth{
		weeklyOnlyClaudeAuth("hey", "0.4", "1794063600"),
		weeklyOnlyClaudeAuth("caprock", "0.98", "1793869200"),
		weeklyOnlyClaudeAuth("gmail", "0.25", "1794092400"),
	}

	for i := 0; i < 4; i++ {
		got, errPick := selector.Pick(context.Background(), "claude", "claude-opus-5-5", cliproxyexecutor.Options{}, auths)
		if errPick != nil {
			t.Fatalf("Pick() #%d error = %v", i, errPick)
		}
		if got == nil || got.ID != "caprock" {
			t.Fatalf("Pick() #%d auth = %v, want caprock", i, got)
		}
	}
}

func TestRoundRobinSelector_MixedFiveHourSignalTreatsMissingAsNoFiveHourLoad(t *testing.T) {
	t.Parallel()

	selector := &RoundRobinSelector{}
	auths := []*Auth{
		claudeWindowAuth("soon", "0.70", "1000"),
		weeklyOnlyClaudeAuth("weekly-only", "0.30", "9000"),
		claudeWindowAuth("busy", "0.90", "8000"),
	}

	want := []string{"soon", "weekly-only", "soon", "weekly-only"}
	for i, id := range want {
		got, errPick := selector.Pick(context.Background(), "claude", "claude-opus-5-5", cliproxyexecutor.Options{}, auths)
		if errPick != nil {
			t.Fatalf("Pick() #%d error = %v", i, errPick)
		}
		if got == nil || got.ID != id {
			t.Fatalf("Pick() #%d auth = %v, want %s", i, got, id)
		}
	}
}
