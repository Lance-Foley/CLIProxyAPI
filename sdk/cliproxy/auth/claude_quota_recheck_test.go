package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const (
	quotaRecheckOpus  = "claude-opus-5-5"
	quotaRecheckFable = "claude-fable-5-2"
)

// quotaRecheckError is a Claude-like upstream error with a status, an optional
// retry hint and a credential scope.
type quotaRecheckError struct {
	status           int
	retryAfter       *time.Duration
	credentialScoped bool
}

func (e quotaRecheckError) Error() string                { return http.StatusText(e.status) }
func (e quotaRecheckError) StatusCode() int              { return e.status }
func (e quotaRecheckError) RetryAfter() *time.Duration   { return e.retryAfter }
func (e quotaRecheckError) IsCredentialScoped() bool     { return e.credentialScoped }
func (e quotaRecheckError) IsRequestScoped() bool        { return false }
func (e quotaRecheckError) Headers() http.Header         { return nil }
func (e quotaRecheckError) ResponseBody() []byte         { return nil }
func (e quotaRecheckError) UpstreamStatusCode() int      { return e.status }
func (e quotaRecheckError) UpstreamErrorMessage() string { return "" }

// quotaRecheckExecutor answers every request with a completed response, or with
// failErr when it is set.
type quotaRecheckExecutor struct {
	mu      sync.Mutex
	failErr error
	models  []string
}

func (e *quotaRecheckExecutor) Identifier() string { return "claude" }

func (e *quotaRecheckExecutor) record(model string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.models = append(e.models, model)
	return e.failErr
}

func (e *quotaRecheckExecutor) calls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.models...)
}

func (e *quotaRecheckExecutor) Execute(_ context.Context, _ *Auth, req cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if errFail := e.record(req.Model); errFail != nil {
		return cliproxyexecutor.Response{}, errFail
	}
	return cliproxyexecutor.Response{Payload: []byte(`{"type":"response.completed","response":{"status":"completed"}}`)}, nil
}

func (e *quotaRecheckExecutor) ExecuteStream(_ context.Context, _ *Auth, req cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if errFail := e.record(req.Model); errFail != nil {
		return nil, errFail
	}
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(`data: {"type":"response.completed","response":{"status":"completed"}}`)}
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func (e *quotaRecheckExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (e *quotaRecheckExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *quotaRecheckExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

type quotaRecheckFixture struct {
	manager  *Manager
	executor *quotaRecheckExecutor
	auth     *Auth
	now      time.Time
	probes   []claudeQuotaRecheckKey
}

// newQuotaRecheckFixture registers one Claude auth with Opus and Fable. The probe
// hook records each call and then runs the real account-pinned VerifyInference.
func newQuotaRecheckFixture(t *testing.T, mutate func(*Auth)) *quotaRecheckFixture {
	t.Helper()
	fx := &quotaRecheckFixture{
		manager:  NewManager(nil, nil, nil),
		executor: &quotaRecheckExecutor{},
		now:      time.Now(),
	}
	fx.manager.RegisterExecutor(fx.executor)
	fx.auth = &Auth{
		ID:       uuid.NewString() + "-claude-recheck",
		Provider: "claude",
		Label:    "recheck-test",
		Status:   StatusActive,
		Attributes: map[string]string{
			"api_key": "test-key",
		},
	}
	if mutate != nil {
		mutate(fx.auth)
	}
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(fx.auth.ID, "claude", []*registry.ModelInfo{{ID: quotaRecheckOpus}, {ID: quotaRecheckFable}})
	t.Cleanup(func() { reg.UnregisterClient(fx.auth.ID) })
	if _, errRegister := fx.manager.Register(WithSkipPersist(context.Background()), fx.auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	fx.manager.quotaRecheck.now = func() time.Time { return fx.now }
	fx.manager.quotaRecheck.probe = func(ctx context.Context, authID, model string) error {
		fx.probes = append(fx.probes, claudeQuotaRecheckKey{authID: authID, model: model})
		return fx.manager.verifyClaudeQuotaProbe(ctx, authID, model)
	}
	return fx
}

func (fx *quotaRecheckFixture) markQuota(t *testing.T, model string, retryAfter time.Duration, credentialScope bool) {
	t.Helper()
	fx.manager.MarkResult(context.Background(), Result{
		AuthID:          fx.auth.ID,
		Provider:        "claude",
		Model:           model,
		Success:         false,
		RetryAfter:      &retryAfter,
		CredentialScope: credentialScope,
		Error:           &Error{HTTPStatus: http.StatusTooManyRequests, Message: "rate limited"},
	})
}

func (fx *quotaRecheckFixture) snapshot(t *testing.T) *Auth {
	t.Helper()
	auth, ok := fx.manager.GetByID(fx.auth.ID)
	if !ok || auth == nil {
		t.Fatal("auth not found")
	}
	return auth
}

func (fx *quotaRecheckFixture) selectable(model string) bool {
	auth, _, errPick := fx.manager.pickNext(context.Background(), "claude", model, cliproxyexecutor.Options{}, map[string]struct{}{})
	return errPick == nil && auth != nil && auth.ID == fx.auth.ID
}

func TestClaudeQuotaRecheck_CredentialCooldownProbeSuccessMakesAuthSelectable(t *testing.T) {
	fx := newQuotaRecheckFixture(t, nil)
	fx.markQuota(t, quotaRecheckOpus, 2*24*time.Hour, true)

	before := fx.snapshot(t)
	if before.Quota.Reason != "credential_quota" || !before.Quota.NextRecoverAt.After(fx.now.Add(24*time.Hour)) {
		t.Fatalf("setup quota = %+v, want a far credential_quota cooldown", before.Quota)
	}
	if fx.selectable(quotaRecheckOpus) {
		t.Fatal("setup: auth is selectable during the credential cooldown")
	}

	fx.manager.recheckClaudeQuotaCooldowns(context.Background())

	if got := fx.executor.calls(); len(got) != 1 {
		t.Fatalf("upstream probe calls = %v, want exactly one", got)
	}
	after := fx.snapshot(t)
	if after.Quota.Exceeded || after.Quota.Reason != "" || !after.Quota.NextRecoverAt.IsZero() || after.Unavailable || !after.NextRetryAfter.IsZero() {
		t.Fatalf("after probe success: quota = %+v unavailable = %v next = %v; want cleared", after.Quota, after.Unavailable, after.NextRetryAfter)
	}
	for model, state := range after.ModelStates {
		if state != nil && isModelStateActiveCooldown(state, time.Now()) {
			t.Fatalf("model %s still cools after probe success: %+v", model, state.Quota)
		}
	}
	for _, model := range []string{quotaRecheckOpus, quotaRecheckFable} {
		if !fx.selectable(model) {
			t.Fatalf("auth is not selectable for %s after probe success", model)
		}
	}
}

func TestClaudeQuotaRecheck_ProbePrefersModelWithoutOwnBlock(t *testing.T) {
	fx := newQuotaRecheckFixture(t, nil)
	// Fable has its own weekly block first, then the shared credential cooldown wraps it.
	fx.markQuota(t, quotaRecheckFable, 3*24*time.Hour, false)
	fx.markQuota(t, quotaRecheckOpus, 2*24*time.Hour, true)

	fx.manager.recheckClaudeQuotaCooldowns(context.Background())

	if len(fx.probes) != 1 || fx.probes[0].model != quotaRecheckOpus {
		t.Fatalf("probes = %+v, want one probe on %s", fx.probes, quotaRecheckOpus)
	}
}

func TestClaudeQuotaRecheck_ModelCooldownProbeSuccessClearsOnlyThatModel(t *testing.T) {
	fx := newQuotaRecheckFixture(t, nil)
	fx.markQuota(t, quotaRecheckFable, 3*24*time.Hour, false)
	if fx.selectable(quotaRecheckFable) {
		t.Fatal("setup: Fable is selectable during its model cooldown")
	}

	fx.manager.recheckClaudeQuotaCooldowns(context.Background())

	if len(fx.probes) != 1 || fx.probes[0].model != quotaRecheckFable {
		t.Fatalf("probes = %+v, want one probe on %s", fx.probes, quotaRecheckFable)
	}
	state := fx.snapshot(t).ModelStates[quotaRecheckFable]
	if state == nil || isModelStateActiveCooldown(state, time.Now()) || state.Quota.Exceeded || state.Quota.BackoffLevel != 0 {
		t.Fatalf("Fable state after probe success = %+v, want cleared", state)
	}
	if !fx.selectable(quotaRecheckFable) {
		t.Fatal("Fable is not selectable after probe success")
	}
}

func TestClaudeQuotaRecheck_ModelCooldownHookSuccessClearsState(t *testing.T) {
	fx := newQuotaRecheckFixture(t, nil)
	fx.markQuota(t, quotaRecheckFable, 3*24*time.Hour, false)
	// A probe hook that does not record a result still clears the model cooldown.
	fx.manager.quotaRecheck.probe = func(context.Context, string, string) error { return nil }

	fx.manager.recheckClaudeQuotaCooldowns(context.Background())

	state := fx.snapshot(t).ModelStates[quotaRecheckFable]
	if state == nil || isModelStateActiveCooldown(state, time.Now()) {
		t.Fatalf("Fable state after hook success = %+v, want cleared", state)
	}
}

func TestClaudeQuotaRecheck_RateLimitedProbeKeepsCooldownAndBackoff(t *testing.T) {
	t.Run("credential cooldown with retry hint", func(t *testing.T) {
		fx := newQuotaRecheckFixture(t, nil)
		fx.markQuota(t, quotaRecheckOpus, 2*24*time.Hour, true)
		before := fx.snapshot(t)

		shortHint := time.Hour
		fx.executor.failErr = quotaRecheckError{status: http.StatusTooManyRequests, retryAfter: &shortHint, credentialScoped: true}
		fx.manager.recheckClaudeQuotaCooldowns(context.Background())

		after := fx.snapshot(t)
		if after.Quota.Reason != "credential_quota" || !after.Quota.Exceeded {
			t.Fatalf("quota after 429 probe = %+v, want credential_quota kept", after.Quota)
		}
		if !after.Quota.NextRecoverAt.Equal(before.Quota.NextRecoverAt) {
			t.Fatalf("deadline moved from %v to %v; a shorter hint must not shorten it", before.Quota.NextRecoverAt, after.Quota.NextRecoverAt)
		}
		if after.Quota.BackoffLevel != before.Quota.BackoffLevel {
			t.Fatalf("backoff level %d -> %d; want unchanged", before.Quota.BackoffLevel, after.Quota.BackoffLevel)
		}
		if fx.selectable(quotaRecheckOpus) {
			t.Fatal("auth became selectable after a 429 probe")
		}
	})

	t.Run("model cooldown from backoff without retry hint", func(t *testing.T) {
		fx := newQuotaRecheckFixture(t, nil)
		// Build an exponential backoff state that ends in 25 minutes.
		deadline := time.Now().Add(25 * time.Minute)
		fx.manager.mu.Lock()
		auth := fx.manager.auths[fx.auth.ID]
		state := ensureModelState(auth, quotaRecheckFable)
		state.Unavailable = true
		state.Status = StatusError
		state.NextRetryAfter = deadline
		state.Quota = QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: deadline, BackoffLevel: 9}
		updateAggregatedAvailability(auth, time.Now())
		fx.manager.mu.Unlock()

		fx.executor.failErr = quotaRecheckError{status: http.StatusTooManyRequests}
		fx.manager.recheckClaudeQuotaCooldowns(context.Background())

		if len(fx.probes) != 1 {
			t.Fatalf("probes = %+v, want one", fx.probes)
		}
		after := fx.snapshot(t).ModelStates[quotaRecheckFable]
		if after == nil || after.Quota.BackoffLevel != 9 || !after.Quota.NextRecoverAt.Equal(deadline) || !after.Quota.Exceeded {
			t.Fatalf("Fable state after 429 probe = %+v, want level 9 and the same deadline", after)
		}
	})

	t.Run("model cooldown with a later real deadline", func(t *testing.T) {
		fx := newQuotaRecheckFixture(t, nil)
		fx.markQuota(t, quotaRecheckFable, 24*time.Hour, false)
		before := fx.snapshot(t).ModelStates[quotaRecheckFable]

		laterHint := 3 * 24 * time.Hour
		fx.executor.failErr = quotaRecheckError{status: http.StatusTooManyRequests, retryAfter: &laterHint}
		fx.manager.recheckClaudeQuotaCooldowns(context.Background())

		after := fx.snapshot(t).ModelStates[quotaRecheckFable]
		if after == nil || !after.Quota.NextRecoverAt.After(before.Quota.NextRecoverAt.Add(24*time.Hour)) {
			t.Fatalf("Fable deadline = %v, want the later upstream deadline (~3d)", after.Quota.NextRecoverAt)
		}
		if after.Quota.BackoffLevel != before.Quota.BackoffLevel {
			t.Fatalf("backoff level %d -> %d; want unchanged", before.Quota.BackoffLevel, after.Quota.BackoffLevel)
		}
		if fx.snapshot(t).Quota.Reason == "credential_quota" {
			t.Fatal("a model-scoped 429 probe cooled the credential")
		}
	})
}

func TestClaudeQuotaRecheck_ShortCooldownIsNotProbed(t *testing.T) {
	fx := newQuotaRecheckFixture(t, nil)
	fx.markQuota(t, quotaRecheckOpus, 10*time.Minute, true)
	fx.markQuota(t, quotaRecheckFable, 10*time.Minute, false)

	fx.manager.recheckClaudeQuotaCooldowns(context.Background())

	if len(fx.probes) != 0 || len(fx.executor.calls()) != 0 {
		t.Fatalf("probes = %+v, upstream calls = %v; want none for a cooldown under 15 minutes", fx.probes, fx.executor.calls())
	}
}

func TestClaudeQuotaRecheck_ThrottlePerAuthAndModel(t *testing.T) {
	fx := newQuotaRecheckFixture(t, nil)
	retryAfter := 2 * 24 * time.Hour
	fx.executor.failErr = quotaRecheckError{status: http.StatusTooManyRequests, retryAfter: &retryAfter, credentialScoped: true}
	fx.markQuota(t, quotaRecheckOpus, retryAfter, true)
	start := fx.now

	fx.manager.recheckClaudeQuotaCooldowns(context.Background())
	if len(fx.probes) != 1 {
		t.Fatalf("first pass probes = %d, want 1", len(fx.probes))
	}

	for _, offset := range []time.Duration{time.Minute, 10 * time.Minute, 29*time.Minute + 59*time.Second} {
		fx.now = start.Add(offset)
		fx.manager.recheckClaudeQuotaCooldowns(context.Background())
		if len(fx.probes) != 1 {
			t.Fatalf("probes after %v = %d, want 1 inside the 30-minute throttle", offset, len(fx.probes))
		}
	}

	fx.now = start.Add(30 * time.Minute)
	fx.manager.recheckClaudeQuotaCooldowns(context.Background())
	if len(fx.probes) != 2 {
		t.Fatalf("probes after 30m = %d, want 2", len(fx.probes))
	}
	if fx.probes[0] != fx.probes[1] {
		t.Fatalf("probe keys = %+v, want the same (auth, model)", fx.probes)
	}
}

func TestClaudeQuotaRecheck_ThrottleIsPerModel(t *testing.T) {
	fx := newQuotaRecheckFixture(t, nil)
	fx.manager.quotaRecheck.probe = func(_ context.Context, authID, model string) error {
		fx.probes = append(fx.probes, claudeQuotaRecheckKey{authID: authID, model: model})
		return quotaRecheckError{status: http.StatusTooManyRequests}
	}
	fx.markQuota(t, quotaRecheckFable, 3*24*time.Hour, false)
	fx.markQuota(t, quotaRecheckOpus, 3*24*time.Hour, false)

	fx.manager.recheckClaudeQuotaCooldowns(context.Background())
	fx.now = fx.now.Add(5 * time.Minute)
	fx.manager.recheckClaudeQuotaCooldowns(context.Background())

	if len(fx.probes) != 2 || fx.probes[0].model != quotaRecheckFable || fx.probes[1].model != quotaRecheckOpus {
		t.Fatalf("probes = %+v, want one probe each for Fable and Opus in order", fx.probes)
	}
}

func TestClaudeQuotaRecheck_SkipsIneligibleAuths(t *testing.T) {
	cases := map[string]func(*Auth){
		"disabled flag":   func(a *Auth) { a.Disabled = true },
		"disabled status": func(a *Auth) { a.Status = StatusDisabled },
		"sign-in":         func(a *Auth) { a.RequiresSignIn = true },
		"other provider":  func(a *Auth) { a.Provider = "codex" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newQuotaRecheckFixture(t, nil)
			fx.markQuota(t, quotaRecheckOpus, 2*24*time.Hour, true)
			fx.markQuota(t, quotaRecheckFable, 2*24*time.Hour, false)
			fx.manager.mu.Lock()
			mutate(fx.manager.auths[fx.auth.ID])
			fx.manager.mu.Unlock()

			fx.manager.recheckClaudeQuotaCooldowns(context.Background())

			if len(fx.probes) != 0 || len(fx.executor.calls()) != 0 {
				t.Fatalf("probes = %+v, upstream calls = %v; want none", fx.probes, fx.executor.calls())
			}
		})
	}
}

func TestClaudeQuotaRecheck_LoopStartsWithAutoRefreshAndStopsOnShutdown(t *testing.T) {
	fx := newQuotaRecheckFixture(t, nil)
	fx.markQuota(t, quotaRecheckOpus, 2*24*time.Hour, true)
	probed := make(chan struct{}, 1)
	fx.manager.quotaRecheck.interval = time.Millisecond
	fx.manager.quotaRecheck.probe = func(context.Context, string, string) error {
		select {
		case probed <- struct{}{}:
		default:
		}
		return quotaRecheckError{status: http.StatusTooManyRequests}
	}

	fx.manager.StartAutoRefresh(context.Background(), time.Hour)
	fx.manager.quotaRecheck.mu.Lock()
	done := fx.manager.quotaRecheck.done
	fx.manager.quotaRecheck.mu.Unlock()
	if done == nil {
		t.Fatal("StartAutoRefresh did not start the quota re-check loop")
	}
	select {
	case <-probed:
	case <-time.After(5 * time.Second):
		t.Fatal("quota re-check loop did not probe")
	}

	fx.manager.StopAutoRefresh()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("quota re-check loop did not stop on StopAutoRefresh")
	}
}

func TestClaudeQuotaRecheck_LoopStopsOnContextCancel(t *testing.T) {
	m := NewManager(nil, nil, nil)
	m.quotaRecheck.interval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	m.startClaudeQuotaRecheck(ctx)
	m.quotaRecheck.mu.Lock()
	done := m.quotaRecheck.done
	m.quotaRecheck.mu.Unlock()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("quota re-check loop did not stop on context cancel")
	}
	m.stopClaudeQuotaRecheck()
}
