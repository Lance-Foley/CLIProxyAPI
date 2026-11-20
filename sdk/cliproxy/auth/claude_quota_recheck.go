package auth

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	log "github.com/sirupsen/logrus"
)

// Anthropic can reset a Claude weekly limit before the advertised reset time. A
// long quota cooldown then benches a healthy account for days. The quota re-check
// loop probes such accounts with a minimal account-pinned request and lifts the
// cooldown when the probe succeeds.
const (
	// claudeQuotaRecheckInterval is how often the loop looks for long cooldowns.
	claudeQuotaRecheckInterval = time.Minute
	// claudeQuotaRecheckMinRemaining skips cooldowns that end soon anyway.
	claudeQuotaRecheckMinRemaining = 15 * time.Minute
	// claudeQuotaRecheckThrottle is the minimum gap between probes of one (auth, model).
	claudeQuotaRecheckThrottle = 30 * time.Minute
)

// claudeQuotaRecheckProbe sends one minimal request for model on the pinned auth.
// A nil error means the upstream accepted the request.
type claudeQuotaRecheckProbe func(ctx context.Context, authID, model string) error

type claudeQuotaRecheckKey struct {
	authID string
	model  string
}

// claudeQuotaRecheckState holds the loop state. The interval, now and probe
// fields are test hooks; zero values select the production defaults.
type claudeQuotaRecheckState struct {
	mu        sync.Mutex
	cancel    context.CancelFunc
	done      chan struct{}
	lastProbe map[claudeQuotaRecheckKey]time.Time

	// runMu serializes passes so probes never overlap, even across a loop restart.
	runMu sync.Mutex

	interval time.Duration
	now      func() time.Time
	probe    claudeQuotaRecheckProbe
}

type claudeQuotaRecheckTarget struct {
	authID          string
	label           string
	model           string
	credentialScope bool
	deadline        time.Time
}

func (m *Manager) claudeQuotaRecheckSettings() (time.Duration, func() time.Time, claudeQuotaRecheckProbe) {
	m.quotaRecheck.mu.Lock()
	defer m.quotaRecheck.mu.Unlock()
	interval := m.quotaRecheck.interval
	if interval <= 0 {
		interval = claudeQuotaRecheckInterval
	}
	now := m.quotaRecheck.now
	if now == nil {
		now = time.Now
	}
	probe := m.quotaRecheck.probe
	if probe == nil {
		probe = m.verifyClaudeQuotaProbe
	}
	return interval, now, probe
}

// startClaudeQuotaRecheck starts the re-check loop. Only one loop is kept alive.
func (m *Manager) startClaudeQuotaRecheck(parent context.Context) {
	if m == nil {
		return
	}
	m.stopClaudeQuotaRecheck()
	interval, _, _ := m.claudeQuotaRecheckSettings()
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	m.quotaRecheck.mu.Lock()
	m.quotaRecheck.cancel = cancel
	m.quotaRecheck.done = done
	m.quotaRecheck.mu.Unlock()
	go m.runClaudeQuotaRecheckLoop(ctx, interval, done)
}

// stopClaudeQuotaRecheck cancels the re-check loop, if it runs.
func (m *Manager) stopClaudeQuotaRecheck() {
	if m == nil {
		return
	}
	m.quotaRecheck.mu.Lock()
	cancel := m.quotaRecheck.cancel
	m.quotaRecheck.cancel = nil
	m.quotaRecheck.done = nil
	m.quotaRecheck.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (m *Manager) runClaudeQuotaRecheckLoop(ctx context.Context, interval time.Duration, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.recheckClaudeQuotaCooldowns(ctx)
		}
	}
}

// recheckClaudeQuotaCooldowns runs one pass: it probes each eligible long Claude
// quota cooldown in sequence, at most once per (auth, model) per throttle window.
func (m *Manager) recheckClaudeQuotaCooldowns(ctx context.Context) {
	if m == nil {
		return
	}
	m.quotaRecheck.runMu.Lock()
	defer m.quotaRecheck.runMu.Unlock()

	_, nowFn, probe := m.claudeQuotaRecheckSettings()
	targets := m.claudeQuotaRecheckTargets(nowFn())
	m.pruneClaudeQuotaRecheckThrottle(nowFn())
	for _, target := range targets {
		if ctx.Err() != nil {
			return
		}
		if !m.claimClaudeQuotaRecheck(target, nowFn()) {
			continue
		}
		m.probeClaudeQuotaTarget(ctx, target, probe, nowFn)
	}
}

func (m *Manager) claimClaudeQuotaRecheck(target claudeQuotaRecheckTarget, now time.Time) bool {
	key := claudeQuotaRecheckKey{authID: target.authID, model: target.model}
	m.quotaRecheck.mu.Lock()
	defer m.quotaRecheck.mu.Unlock()
	if last, ok := m.quotaRecheck.lastProbe[key]; ok && now.Sub(last) < claudeQuotaRecheckThrottle {
		return false
	}
	if m.quotaRecheck.lastProbe == nil {
		m.quotaRecheck.lastProbe = make(map[claudeQuotaRecheckKey]time.Time)
	}
	m.quotaRecheck.lastProbe[key] = now
	return true
}

func (m *Manager) pruneClaudeQuotaRecheckThrottle(now time.Time) {
	m.quotaRecheck.mu.Lock()
	defer m.quotaRecheck.mu.Unlock()
	for key, last := range m.quotaRecheck.lastProbe {
		if now.Sub(last) >= claudeQuotaRecheckThrottle {
			delete(m.quotaRecheck.lastProbe, key)
		}
	}
}

// claudeQuotaRecheckTargets lists the cooldowns to probe, sorted for a stable order.
// An active credential-scope cooldown yields one credential target and hides the
// model cooldowns under it, because no model can recover before the credential.
func (m *Manager) claudeQuotaRecheckTargets(now time.Time) []claudeQuotaRecheckTarget {
	var targets []claudeQuotaRecheckTarget
	for _, auth := range m.List() {
		if !claudeQuotaRecheckEligible(auth) {
			continue
		}
		if auth.Quota.Exceeded && auth.Quota.Reason == "credential_quota" && auth.Quota.NextRecoverAt.After(now) {
			if auth.Quota.NextRecoverAt.Sub(now) <= claudeQuotaRecheckMinRemaining {
				continue
			}
			model := claudeCredentialQuotaProbeModel(auth, registry.GetGlobalRegistry().GetModelsForClient(auth.ID), now)
			if model == "" {
				continue
			}
			targets = append(targets, claudeQuotaRecheckTarget{
				authID:          auth.ID,
				label:           claudeQuotaRecheckLabel(auth),
				model:           model,
				credentialScope: true,
				deadline:        auth.Quota.NextRecoverAt,
			})
			continue
		}
		for modelKey, state := range auth.ModelStates {
			if strings.TrimSpace(modelKey) == "" || state == nil || state.Status == StatusDisabled {
				continue
			}
			if !state.Quota.Exceeded || state.Quota.Reason != "quota" {
				continue
			}
			deadline := state.Quota.NextRecoverAt
			if state.NextRetryAfter.After(deadline) {
				deadline = state.NextRetryAfter
			}
			if deadline.Sub(now) <= claudeQuotaRecheckMinRemaining {
				continue
			}
			targets = append(targets, claudeQuotaRecheckTarget{
				authID:   auth.ID,
				label:    claudeQuotaRecheckLabel(auth),
				model:    modelKey,
				deadline: deadline,
			})
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].authID != targets[j].authID {
			return targets[i].authID < targets[j].authID
		}
		return targets[i].model < targets[j].model
	})
	return targets
}

func claudeQuotaRecheckEligible(auth *Auth) bool {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), "claude") {
		return false
	}
	if auth.Disabled || auth.Status == StatusDisabled || auth.RequiresSignIn {
		return false
	}
	return !hasUnauthorizedAuthFailure(auth)
}

// claudeCredentialQuotaProbeModel picks a model that the credential-scope cooldown
// blocks. It prefers a model whose only block is the credential cooldown, so an
// independent model block (for example a Fable weekly bucket) cannot fail the probe.
func claudeCredentialQuotaProbeModel(auth *Auth, registered []*registry.ModelInfo, now time.Time) string {
	keys := make([]string, 0, len(auth.ModelStates))
	for key := range auth.ModelStates {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	ownBlock := func(key string) bool {
		state := auth.ModelStates[key]
		if state == nil {
			return false
		}
		if state.Status == StatusDisabled {
			return true
		}
		return state.credentialQuotaShadow != nil && isModelStateActiveCooldown(state.credentialQuotaShadow, now)
	}
	for _, key := range keys {
		state := auth.ModelStates[key]
		if state == nil || ownBlock(key) {
			continue
		}
		if state.credentialQuotaPropagated || state.Quota.Reason == "credential_quota" {
			return key
		}
	}
	first := ""
	for _, info := range registered {
		if info == nil || strings.TrimSpace(info.ID) == "" {
			continue
		}
		id := strings.TrimSpace(info.ID)
		if first == "" {
			first = id
		}
		if !ownBlock(canonicalModelKey(id)) {
			return id
		}
	}
	return first
}

// claudeQuotaRecheckLabel names the auth in logs without exposing a secret.
func claudeQuotaRecheckLabel(auth *Auth) string {
	if label := strings.TrimSpace(auth.Label); label != "" {
		return label
	}
	if kind, info := auth.AccountInfo(); kind == "oauth" && info != "" {
		return info
	}
	if name := strings.TrimSpace(auth.FileName); name != "" {
		return name
	}
	return auth.ID
}

// verifyClaudeQuotaProbe is the production probe. It uses the account-pinned
// VerifyInference, which records the result through MarkResult like real traffic.
func (m *Manager) verifyClaudeQuotaProbe(ctx context.Context, authID, model string) error {
	before, okBefore := m.GetByID(authID)
	_, errVerify := m.VerifyInference(ctx, authID, model)
	if errVerify == nil {
		return nil
	}
	// VerifyInference reports credential_superseded after a completed success when
	// an active credential_quota cooldown kept InferenceVerified unset. If the
	// credential did not change, the upstream request succeeded.
	var authErr *Error
	if okBefore && before != nil && errors.As(errVerify, &authErr) && authErr != nil && authErr.Code == "credential_superseded" {
		if after, okAfter := m.GetByID(authID); okAfter && after != nil &&
			after.CredentialVersion == before.CredentialVersion && after.RegistrationEpoch == before.RegistrationEpoch {
			return nil
		}
	}
	return errVerify
}

func (m *Manager) probeClaudeQuotaTarget(ctx context.Context, target claudeQuotaRecheckTarget, probe claudeQuotaRecheckProbe, nowFn func() time.Time) {
	scope := "model"
	if target.credentialScope {
		scope = "credential"
	}
	entry := log.WithFields(log.Fields{
		"auth":           target.label,
		"model":          target.model,
		"scope":          scope,
		"cooldown_until": target.deadline.Format(time.RFC3339),
	})

	errProbe := probe(ctx, target.authID, target.model)
	if errProbe != nil {
		status := statusCodeFromError(errProbe)
		if status == 0 {
			if authErr := resultErrorFromError(errProbe); authErr != nil {
				status = authErr.StatusCode()
			}
		}
		entry.WithField("status", status).Info("claude quota re-check: probe failed, cooldown kept")
		return
	}

	if target.credentialScope {
		// A success never lifts an active credential_quota cooldown in MarkResult,
		// so clear it the same way the manual cooldown reset does.
		if _, _, errReset := m.ResetQuota(ctx, target.authID); errReset != nil {
			entry.Warnf("claude quota re-check: probe succeeded, cooldown reset failed: %v", errReset)
			return
		}
	} else if m.claudeModelCooldownActive(target.authID, target.model, nowFn()) {
		// The production probe already cleared the model through MarkResult. Record
		// a success for any other probe so the model state is fully cleared.
		m.MarkResult(ctx, Result{AuthID: target.authID, Provider: "claude", Model: target.model, Success: true})
	}
	entry.Info("claude quota re-check: probe succeeded, cooldown cleared")
}

func (m *Manager) claudeModelCooldownActive(authID, model string, now time.Time) bool {
	auth, ok := m.GetByID(authID)
	if !ok || auth == nil {
		return false
	}
	state := auth.ModelStates[model]
	return state != nil && isModelStateActiveCooldown(state, now)
}
