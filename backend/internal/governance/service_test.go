//go:build enterprise

package governance

import (
	"context"
	"errors"
	"testing"
)

// memRepo — in-memory Repository для unit-тестов service.
// Evaluate не зависит от PG, поэтому unit-тесты используют этот
// mock без DB-интеграции.
type memRepo struct {
	policy *Policy
	err    error
}

func (m *memRepo) GetActive(ctx context.Context, _ string) (*Policy, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.policy, nil
}

func (m *memRepo) Upsert(ctx context.Context, p *Policy, actor, _ string) (*Policy, error) {
	m.policy = p
	return p, nil
}

// TestEvaluate_NilService_AllowsAll — безопасная дефолт-DI для dev/tests
// деплоев без governance: nil Service возвращает Allow без чтения repo.
// Важно: nil-safe call через метод-receiver-pattern.
func TestEvaluate_NilService_AllowsAll(t *testing.T) {
	var s *Service // nil
	dec, err := s.Evaluate(context.Background(), "", "", "", "", "openai", "gpt-4")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if dec.Kind != DecisionAllow {
		t.Errorf("kind = %v, want Allow", dec.Kind)
	}
	if dec.Code != CodeGovernanceDisabled {
		t.Errorf("code = %q, want %q", dec.Code, CodeGovernanceDisabled)
	}
}

// TestEvaluate_NoPolicyInRepo_AllowsAll — чистый deploy: в БД ни одной
// политики (GetActive вернул nil, nil). Fail-open по замыслу: если
// operator не сконфигурировал governance — продукт не должен ломаться.
// Оператор переходит к deny-by-default только после явного создания
// политики с Mode=allowlist_strict.
func TestEvaluate_NoPolicyInRepo_AllowsAll(t *testing.T) {
	s := NewService(&memRepo{policy: nil})
	dec, err := s.Evaluate(context.Background(), "", "", "", "", "openai", "gpt-4")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if dec.Kind != DecisionAllow {
		t.Errorf("kind = %v, want Allow", dec.Kind)
	}
	if dec.Code != CodeGovernanceDisabled {
		t.Errorf("code = %q, want %q", dec.Code, CodeGovernanceDisabled)
	}
}

// TestEvaluate_ModeDisabled_AllowsAll — явно выставленный disabled
// ведёт себя как отсутствие политики, но возвращает PolicyID (для
// audit-консистентности — оператор видит КАКАЯ именно политика в
// состоянии disabled).
func TestEvaluate_ModeDisabled_AllowsAll(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeDisabled, IsActive: true,
	}})
	dec, err := s.Evaluate(context.Background(), "", "", "", "", "anthropic", "claude-3-opus")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if dec.Kind != DecisionAllow || dec.Code != CodeGovernanceDisabled {
		t.Errorf("got %+v, want Allow/governance_disabled", dec)
	}
}

// TestEvaluate_Strict_AllowsKnownPair — happy path: оба (provider,
// model) присутствуют в allowlist.
func TestEvaluate_Strict_AllowsKnownPair(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistStrict, IsActive: true,
		Rules: []ProviderRule{
			{Provider: "openai", Models: []string{"gpt-4", "gpt-4o-mini"}},
			{Provider: "anthropic", Models: []string{"claude-3-opus"}},
		},
	}})
	dec, _ := s.Evaluate(context.Background(), "", "", "", "", "openai", "gpt-4")
	if dec.Kind != DecisionAllow {
		t.Errorf("kind = %v, want Allow, decision=%+v", dec.Kind, dec)
	}
	if dec.Code != CodeAllowed {
		t.Errorf("code = %q, want %q", dec.Code, CodeAllowed)
	}
	if dec.PolicyID != "p-1" {
		t.Errorf("policy_id = %q, want p-1", dec.PolicyID)
	}
}

// TestEvaluate_Strict_DeniesUnknownProvider — провайдера нет в Rules.
// Это основной deny-by-default use case: оператор явно ограничил
// список провайдеров.
func TestEvaluate_Strict_DeniesUnknownProvider(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistStrict, IsActive: true,
		Rules: []ProviderRule{
			{Provider: "openai", Models: []string{"gpt-4"}},
		},
	}})
	dec, _ := s.Evaluate(context.Background(), "", "", "", "", "gemini", "gemini-pro")
	if dec.Kind != DecisionDeny {
		t.Errorf("kind = %v, want Deny, decision=%+v", dec.Kind, dec)
	}
	if dec.Code != CodeUnknownProvider {
		t.Errorf("code = %q, want %q", dec.Code, CodeUnknownProvider)
	}
	if dec.PolicyID != "p-1" {
		t.Errorf("policy_id = %q, want p-1", dec.PolicyID)
	}
}

// TestEvaluate_Strict_DeniesUnknownModelForKnownProvider — провайдер
// разрешён, но конкретная модель — нет. Это ключевая часть
// model-scoped governance (не только «весь провайдер да/нет», а
// per-model контроль).
func TestEvaluate_Strict_DeniesUnknownModelForKnownProvider(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistStrict, IsActive: true,
		Rules: []ProviderRule{
			{Provider: "openai", Models: []string{"gpt-4o-mini"}},
		},
	}})
	dec, _ := s.Evaluate(context.Background(), "", "", "", "", "openai", "gpt-4")
	if dec.Kind != DecisionDeny {
		t.Errorf("kind = %v, want Deny", dec.Kind)
	}
	if dec.Code != CodeUnknownModel {
		t.Errorf("code = %q, want %q", dec.Code, CodeUnknownModel)
	}
}

// TestEvaluate_Strict_EmptyRules_DeniesAll — strict mode + пустой
// Rules (оператор создал политику, но ещё не добавил правил).
// Fail-closed: всё запрещено. Это корректное поведение для
// deny-by-default; если политика создана — она должна явно что-то
// разрешать.
func TestEvaluate_Strict_EmptyRules_DeniesAll(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistStrict, IsActive: true,
		Rules: nil,
	}})
	dec, _ := s.Evaluate(context.Background(), "", "", "", "", "openai", "gpt-4")
	if dec.Kind != DecisionDeny {
		t.Errorf("kind = %v, want Deny", dec.Kind)
	}
	if dec.Code != CodeUnknownProvider {
		t.Errorf("code = %q, want %q", dec.Code, CodeUnknownProvider)
	}
}

// TestEvaluate_Strict_EmptyModelsInRule_DeniesAllModels —
// провайдер есть в Rules, но Models пустой. Интерпретация: «никакие
// модели этого провайдера не разрешены». Deny с unknown_model, не
// unknown_provider (provider-то мы нашли, не нашли model).
func TestEvaluate_Strict_EmptyModelsInRule_DeniesAllModels(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistStrict, IsActive: true,
		Rules: []ProviderRule{
			{Provider: "openai", Models: []string{}},
		},
	}})
	dec, _ := s.Evaluate(context.Background(), "", "", "", "", "openai", "gpt-4")
	if dec.Kind != DecisionDeny {
		t.Errorf("kind = %v, want Deny", dec.Kind)
	}
	if dec.Code != CodeUnknownModel {
		t.Errorf("code = %q, want %q", dec.Code, CodeUnknownModel)
	}
}

// TestEvaluate_Strict_CaseInsensitiveMatch — provider/model
// идентификаторы case-insensitive. OpenAI иногда приходит как
// "OpenAI", иногда как "openai"; модели — "GPT-4" vs "gpt-4".
// Policy не должна зависеть от регистра.
func TestEvaluate_Strict_CaseInsensitiveMatch(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistStrict, IsActive: true,
		Rules: []ProviderRule{
			{Provider: "OpenAI", Models: []string{"GPT-4"}},
		},
	}})
	dec, _ := s.Evaluate(context.Background(), "", "", "", "", "openai", "gpt-4")
	if dec.Kind != DecisionAllow {
		t.Errorf("kind = %v, want Allow (case-insensitive)", dec.Kind)
	}
}

// TestEvaluate_RepoError_FailClosed — критичный тест: при ошибке
// чтения из БД (tx timeout, connection loss) мы НЕ должны пропускать
// запрос (fail-open ослабит compliance). Deny с кодом
// policy_read_failure.
//
// Philosophy: governance — это compliance-control. Если control не
// работает (policy unreadable), безопаснее отказать в запросе, чем
// пропустить. Оператор получит 403, поймёт что есть проблема.
// Fail-open для availability недопустим.
func TestEvaluate_RepoError_FailClosed(t *testing.T) {
	s := NewService(&memRepo{err: errors.New("connection lost")})
	dec, err := s.Evaluate(context.Background(), "", "", "", "", "openai", "gpt-4")
	if err == nil {
		t.Error("err = nil, want non-nil (caller должен видеть root cause)")
	}
	if dec.Kind != DecisionDeny {
		t.Errorf("kind = %v, want Deny (fail-closed)", dec.Kind)
	}
	if dec.Code != CodePolicyReadFailure {
		t.Errorf("code = %q, want %q", dec.Code, CodePolicyReadFailure)
	}
}

// TestEvaluate_DuplicateProviderCaseVariants_MergesMatches — review-
// finding: старая реализация останавливалась на первом matching
// provider rule и сразу возвращала unknown_model, если модель не
// в нём — даже если она присутствовала во втором matching rule
// (например duplicate из-за case-only разницы openai vs OpenAI).
// После fix'а Evaluate обходит все matching rules.
func TestEvaluate_DuplicateProviderCaseVariants_MergesMatches(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistStrict, IsActive: true,
		Rules: []ProviderRule{
			// Admin каким-то образом положил две строки с case-only
			// разницей в Rules (прямой SQL, баг UI, импорт). До fix'а
			// Evaluate возвращал Deny на gpt-4o-mini, потому что
			// первый matching rule (OpenAI) содержит только gpt-4.
			{Provider: "OpenAI", Models: []string{"gpt-4"}},
			{Provider: "openai", Models: []string{"gpt-4o-mini"}},
		},
	}})
	dec, _ := s.Evaluate(context.Background(), "", "", "", "", "openai", "gpt-4o-mini")
	if dec.Kind != DecisionAllow {
		t.Errorf("kind = %v, want Allow (модель присутствует во втором matching rule), decision=%+v", dec.Kind, dec)
	}
}

// TestEvaluate_DuplicateProviderExact_MergesMatches — тот же случай,
// но без case-разницы: две записи для одного provider (strict dup).
// Evaluate должен считать union моделей.
func TestEvaluate_DuplicateProviderExact_MergesMatches(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistStrict, IsActive: true,
		Rules: []ProviderRule{
			{Provider: "openai", Models: []string{"gpt-4"}},
			{Provider: "openai", Models: []string{"gpt-4o"}},
		},
	}})
	dec, _ := s.Evaluate(context.Background(), "", "", "", "", "openai", "gpt-4o")
	if dec.Kind != DecisionAllow {
		t.Errorf("kind = %v, want Allow для модели из второго rule", dec.Kind)
	}
}

// TestEvaluate_DuplicateProvider_ModelInNeitherRule — если ни один
// из matching rules не содержит модель, возвращаем unknown_model
// (а не unknown_provider — провайдер-то нашли).
func TestEvaluate_DuplicateProvider_ModelInNeitherRule(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistStrict, IsActive: true,
		Rules: []ProviderRule{
			{Provider: "openai", Models: []string{"gpt-4"}},
			{Provider: "openai", Models: []string{"gpt-4o"}},
		},
	}})
	dec, _ := s.Evaluate(context.Background(), "", "", "", "", "openai", "gpt-5-beta")
	if dec.Kind != DecisionDeny || dec.Code != CodeUnknownModel {
		t.Errorf("got %+v, want Deny/unknown_model", dec)
	}
}

// TestUpsert_NormalizesProviderCasing — review-fix: Service.Upsert
// приводит provider/models к lowercase и merge'ит duplicates ДО
// persist. В БД всегда canonical form — защита от человеческих
// ошибок в UI и от direct-SQL редактирования.
func TestUpsert_NormalizesProviderCasing(t *testing.T) {
	repo := &memRepo{}
	s := NewService(repo)
	p := &Policy{
		Mode: ModeAllowlistStrict,
		Rules: []ProviderRule{
			{Provider: "OpenAI", Models: []string{"GPT-4", "gpt-4o"}},
		},
	}
	saved, err := s.Upsert(context.Background(), p, "u-admin", "")
	if err != nil {
		t.Fatalf("upsert err: %v", err)
	}
	if len(saved.Rules) != 1 {
		t.Fatalf("rules = %+v, want 1", saved.Rules)
	}
	if saved.Rules[0].Provider != "openai" {
		t.Errorf("provider = %q, want lowercase openai", saved.Rules[0].Provider)
	}
	// Модели в lowercase.
	for _, m := range saved.Rules[0].Models {
		if m != "gpt-4" && m != "gpt-4o" {
			t.Errorf("model %q не нормализован в lowercase", m)
		}
	}
}

// TestUpsert_MergesDuplicateProviders — две записи одного provider
// (разные casing) сливаются в одну canonical с union моделей.
func TestUpsert_MergesDuplicateProviders(t *testing.T) {
	repo := &memRepo{}
	s := NewService(repo)
	p := &Policy{
		Mode: ModeAllowlistStrict,
		Rules: []ProviderRule{
			{Provider: "OpenAI", Models: []string{"gpt-4"}},
			{Provider: "openai", Models: []string{"gpt-4o-mini"}},
		},
	}
	saved, _ := s.Upsert(context.Background(), p, "u-admin", "")
	if len(saved.Rules) != 1 {
		t.Fatalf("rules count = %d, want 1 (duplicates merged), rules=%+v", len(saved.Rules), saved.Rules)
	}
	got := saved.Rules[0]
	if got.Provider != "openai" {
		t.Errorf("provider = %q, want openai", got.Provider)
	}
	if len(got.Models) != 2 {
		t.Errorf("models = %v, want [gpt-4, gpt-4o-mini]", got.Models)
	}
}

// TestUpsert_DedupesModelsWithinRule — дубликаты моделей внутри
// одного rule схлопываются, включая case-only duplicates.
func TestUpsert_DedupesModelsWithinRule(t *testing.T) {
	repo := &memRepo{}
	s := NewService(repo)
	p := &Policy{
		Mode: ModeAllowlistStrict,
		Rules: []ProviderRule{
			{Provider: "openai", Models: []string{"gpt-4", "GPT-4", "gpt-4"}},
		},
	}
	saved, _ := s.Upsert(context.Background(), p, "u-admin", "")
	if len(saved.Rules) != 1 || len(saved.Rules[0].Models) != 1 {
		t.Fatalf("expected 1 rule with 1 model, got %+v", saved.Rules)
	}
}

// TestUpsert_SkipsEmptyProviderName — пустой provider name отсекается.
// Админ случайно нажал «добавить rule» без названия — не должно
// упасть и не должно пробиться в БД.
func TestUpsert_SkipsEmptyProviderName(t *testing.T) {
	repo := &memRepo{}
	s := NewService(repo)
	p := &Policy{
		Mode: ModeAllowlistStrict,
		Rules: []ProviderRule{
			{Provider: "", Models: []string{"x"}},
			{Provider: "openai", Models: []string{"gpt-4"}},
		},
	}
	saved, _ := s.Upsert(context.Background(), p, "u-admin", "")
	if len(saved.Rules) != 1 || saved.Rules[0].Provider != "openai" {
		t.Errorf("empty-provider rule не отсечён: %+v", saved.Rules)
	}
}

// TestUpsert_StableOrdering — провайдеры сохраняются в
// detrministic-порядке (alphabetical по canonical name). Это важно
// для UI (list не «прыгает» между save'ами) и для
// deterministic-тестов.
func TestUpsert_StableOrdering(t *testing.T) {
	repo := &memRepo{}
	s := NewService(repo)
	p := &Policy{
		Mode: ModeAllowlistStrict,
		Rules: []ProviderRule{
			{Provider: "openai", Models: []string{"gpt-4"}},
			{Provider: "anthropic", Models: []string{"claude-3"}},
			{Provider: "gemini", Models: []string{"pro"}},
		},
	}
	saved, _ := s.Upsert(context.Background(), p, "u-admin", "")
	if len(saved.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(saved.Rules))
	}
	wantOrder := []string{"anthropic", "gemini", "openai"}
	for i, w := range wantOrder {
		if saved.Rules[i].Provider != w {
			t.Errorf("[%d] provider = %q, want %q", i, saved.Rules[i].Provider, w)
		}
	}
}

// TestMode_IsValid — проверка валидатора для handler'а (admin UI
// может прислать typo или unknown tag).
func TestMode_IsValid(t *testing.T) {
	cases := []struct {
		in   Mode
		want bool
	}{
		{ModeDisabled, true},
		{ModeAllowlistStrict, true},
		{ModeAllowlistRoleBased, true}, // PR-G2
		{"", false},
		{"device_scope", false}, // G3+ не реализован
		{"ALLOWLIST_STRICT", false}, // case-sensitive для хранимого значения
	}
	for _, c := range cases {
		if got := c.in.IsValid(); got != c.want {
			t.Errorf("IsValid(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// --- PR-G2: Role-based Evaluate tests ---

func TestEvaluate_RoleBased_AllowsKnownTriple(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistRoleBased, IsActive: true,
		RoleRules: []RoleRule{
			{Role: "admin", Rules: []ProviderRule{
				{Provider: "openai", Models: []string{"gpt-4o"}},
			}},
			{Role: "analyst", Rules: []ProviderRule{
				{Provider: "openai", Models: []string{"gpt-4o-mini"}},
			}},
		},
	}})
	dec, _ := s.Evaluate(context.Background(), "", "admin", "", "", "openai", "gpt-4o")
	if dec.Kind != DecisionAllow || dec.Code != CodeAllowed {
		t.Errorf("admin/openai/gpt-4o: %+v, want Allow/allowed", dec)
	}
	dec, _ = s.Evaluate(context.Background(), "", "analyst", "", "", "openai", "gpt-4o-mini")
	if dec.Kind != DecisionAllow {
		t.Errorf("analyst/openai/gpt-4o-mini: %+v, want Allow", dec)
	}
}

// TestEvaluate_RoleBased_DeniesPrivilegedModelForLesserRole —
// ключевой role-based scenario: analyst пытается admin-only модель.
func TestEvaluate_RoleBased_DeniesPrivilegedModelForLesserRole(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistRoleBased, IsActive: true,
		RoleRules: []RoleRule{
			{Role: "admin", Rules: []ProviderRule{
				{Provider: "openai", Models: []string{"gpt-4o"}},
			}},
			{Role: "analyst", Rules: []ProviderRule{
				{Provider: "openai", Models: []string{"gpt-4o-mini"}},
			}},
		},
	}})
	dec, _ := s.Evaluate(context.Background(), "", "analyst", "", "", "openai", "gpt-4o")
	if dec.Kind != DecisionDeny || dec.Code != CodeUnknownModel {
		t.Errorf("analyst privileged model: %+v, want Deny/unknown_model", dec)
	}
}

// TestEvaluate_RoleBased_UnknownRole_Denied — role не в RoleRules
// → Deny/unknown_role (deny-by-default).
func TestEvaluate_RoleBased_UnknownRole_Denied(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistRoleBased, IsActive: true,
		RoleRules: []RoleRule{
			{Role: "admin", Rules: []ProviderRule{
				{Provider: "openai", Models: []string{"gpt-4o"}},
			}},
		},
	}})
	dec, _ := s.Evaluate(context.Background(), "", "intern", "", "", "openai", "gpt-4o")
	if dec.Kind != DecisionDeny || dec.Code != CodeUnknownRole {
		t.Errorf("unknown role: %+v, want Deny/unknown_role", dec)
	}
}

// TestEvaluate_RoleBased_EmptyRoleRules_DeniesAll — misconfigured
// policy (Mode=role_based, RoleRules=[]) → любой запрос deny.
func TestEvaluate_RoleBased_EmptyRoleRules_DeniesAll(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistRoleBased, IsActive: true,
	}})
	dec, _ := s.Evaluate(context.Background(), "", "admin", "", "", "openai", "gpt-4o")
	if dec.Kind != DecisionDeny || dec.Code != CodeUnknownRole {
		t.Errorf("empty role_rules: %+v, want Deny/unknown_role", dec)
	}
}

// TestEvaluate_RoleBased_UnknownProvider — role matched, provider
// outside role's scope → unknown_provider.
func TestEvaluate_RoleBased_UnknownProvider(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistRoleBased, IsActive: true,
		RoleRules: []RoleRule{
			{Role: "admin", Rules: []ProviderRule{
				{Provider: "openai", Models: []string{"gpt-4o"}},
			}},
		},
	}})
	dec, _ := s.Evaluate(context.Background(), "", "admin", "", "", "anthropic", "claude-3")
	if dec.Kind != DecisionDeny || dec.Code != CodeUnknownProvider {
		t.Errorf("unknown provider in role scope: %+v", dec)
	}
}

// TestEvaluate_RoleBased_CaseInsensitive — Admin/admin,
// OpenAI/openai, GPT-4/gpt-4 все match'аются.
func TestEvaluate_RoleBased_CaseInsensitive(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistRoleBased, IsActive: true,
		RoleRules: []RoleRule{
			{Role: "Admin", Rules: []ProviderRule{
				{Provider: "OpenAI", Models: []string{"GPT-4"}},
			}},
		},
	}})
	dec, _ := s.Evaluate(context.Background(), "", "admin", "", "", "openai", "gpt-4")
	if dec.Kind != DecisionAllow {
		t.Errorf("case-insensitive triple: %+v, want Allow", dec)
	}
}

// TestEvaluate_StrictMode_IgnoresRole — backward compat с PR-G1.
// Mode=allowlist_strict не использует role.
func TestEvaluate_StrictMode_IgnoresRole(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistStrict, IsActive: true,
		Rules: []ProviderRule{
			{Provider: "openai", Models: []string{"gpt-4o"}},
		},
	}})
	dec, _ := s.Evaluate(context.Background(), "", "intern", "", "", "openai", "gpt-4o")
	if dec.Kind != DecisionAllow {
		t.Errorf("strict mode should ignore role: %+v", dec)
	}
}

// TestUpsert_RoleBased_NormalizesRoleNames — roles lowercase,
// duplicate-role merge с union моделей, alphabetical sort.
func TestUpsert_RoleBased_NormalizesRoleNames(t *testing.T) {
	repo := &memRepo{}
	s := NewService(repo)
	p := &Policy{
		Mode: ModeAllowlistRoleBased,
		RoleRules: []RoleRule{
			{Role: "Admin", Rules: []ProviderRule{{Provider: "openai", Models: []string{"gpt-4"}}}},
			{Role: "admin", Rules: []ProviderRule{{Provider: "openai", Models: []string{"gpt-4o"}}}},
			{Role: "analyst", Rules: []ProviderRule{{Provider: "openai", Models: []string{"gpt-4o-mini"}}}},
		},
	}
	saved, err := s.Upsert(context.Background(), p, "u-admin", "")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// Admin + admin → merged в один с union models.
	if len(saved.RoleRules) != 2 {
		t.Fatalf("role_rules count = %d, want 2, got %+v", len(saved.RoleRules), saved.RoleRules)
	}
	if saved.RoleRules[0].Role != "admin" || saved.RoleRules[1].Role != "analyst" {
		t.Errorf("role sort: %+v", saved.RoleRules)
	}
	if len(saved.RoleRules[0].Rules) != 1 {
		t.Errorf("admin provider rules: %+v", saved.RoleRules[0].Rules)
	}
	if len(saved.RoleRules[0].Rules[0].Models) != 2 {
		t.Errorf("admin union models: %+v", saved.RoleRules[0].Rules[0].Models)
	}
}

// TestEvaluate_RoleBased_DuplicateRoleEntries_MergesMatches —
// PR-G2.1 regression: duplicate RoleRule entries (admin + Admin
// с split model sets) могли попасть в БД через direct SQL или
// legacy import. Read-path не нормализует, поэтому Evaluate
// обязан обходить ВСЕ matching role entries (defence-in-depth
// аналогично duplicate-provider fix в PR-G1 review).
func TestEvaluate_RoleBased_DuplicateRoleEntries_MergesMatches(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-1", Mode: ModeAllowlistRoleBased, IsActive: true,
		RoleRules: []RoleRule{
			// Direct-SQL инжекция duplicate roles; case отличается.
			// Второй entry содержит gpt-4o-mini — модель, которая
			// ДОЛЖНА быть allowed для admin.
			{Role: "Admin", Rules: []ProviderRule{
				{Provider: "openai", Models: []string{"gpt-4"}},
			}},
			{Role: "admin", Rules: []ProviderRule{
				{Provider: "openai", Models: []string{"gpt-4o-mini"}},
			}},
		},
	}})
	// gpt-4o-mini присутствует только во ВТОРОЙ role entry.
	// Pre-fix: early-return на первом "Admin" match → Deny/unknown_model.
	// Post-fix: все matching merge'ятся → Allow.
	dec, _ := s.Evaluate(context.Background(), "", "admin", "", "", "openai", "gpt-4o-mini")
	if dec.Kind != DecisionAllow {
		t.Errorf("gpt-4o-mini in second duplicate role entry: %+v, want Allow", dec)
	}
	// Симметрично: gpt-4 из первой role entry тоже allowed.
	dec, _ = s.Evaluate(context.Background(), "", "admin", "", "", "openai", "gpt-4")
	if dec.Kind != DecisionAllow {
		t.Errorf("gpt-4 in first duplicate role entry: %+v, want Allow", dec)
	}
	// Модель, которой нет ни в одной → unknown_model (не unknown_role:
	// роль-то мы нашли).
	dec, _ = s.Evaluate(context.Background(), "", "admin", "", "", "openai", "gpt-5-beta")
	if dec.Kind != DecisionDeny || dec.Code != CodeUnknownModel {
		t.Errorf("model in neither entry: %+v, want Deny/unknown_model", dec)
	}
}

// TestUpsert_RoleBased_SkipsEmptyRoleName.
func TestUpsert_RoleBased_SkipsEmptyRoleName(t *testing.T) {
	repo := &memRepo{}
	s := NewService(repo)
	p := &Policy{
		Mode: ModeAllowlistRoleBased,
		RoleRules: []RoleRule{
			{Role: "", Rules: []ProviderRule{{Provider: "x", Models: []string{"y"}}}},
			{Role: "admin", Rules: []ProviderRule{{Provider: "openai", Models: []string{"gpt-4o"}}}},
		},
	}
	saved, _ := s.Upsert(context.Background(), p, "u-admin", "")
	if len(saved.RoleRules) != 1 || saved.RoleRules[0].Role != "admin" {
		t.Errorf("empty role не отсечён: %+v", saved.RoleRules)
	}
}

// ---------------------------------------------------------------------------
// PR-G3: context_scoped mode tests
// ---------------------------------------------------------------------------

func financeContextPolicy() *Policy {
	return &Policy{
		ID:   "ctx-policy-1",
		Mode: ModeContextScoped,
		ContextRules: []ContextRule{
			{
				Department:  "finance",
				Role:        "analyst",
				Sensitivity: []SensitivityLevel{SensitivityConfidential, SensitivityStandard},
				Rules:       []ProviderRule{{Provider: "openai", Models: []string{"gpt-4"}}},
			},
			{
				Department:  "finance",
				Role:        "*", // any role
				Sensitivity: []SensitivityLevel{SensitivityStandard},
				Rules:       []ProviderRule{{Provider: "ollama", Models: []string{"llama3"}}},
			},
			{
				Department:  "hr",
				Sensitivity: []SensitivityLevel{SensitivityStandard, SensitivityConfidential},
				Rules:       []ProviderRule{{Provider: "anthropic", Models: []string{"claude-3-haiku"}}},
			},
		},
		IsActive: true,
	}
}

// TestEvaluate_ContextScoped_AllowsMatchingContext — full match.
func TestEvaluate_ContextScoped_AllowsMatchingContext(t *testing.T) {
	s := NewService(&memRepo{policy: financeContextPolicy()})
	dec, _ := s.Evaluate(context.Background(), "", "analyst", "finance", "confidential", "openai", "gpt-4")
	if dec.Kind != DecisionAllow {
		t.Errorf("full context match: got %+v, want Allow", dec)
	}
	if dec.MatchedRuleIndex != 0 {
		t.Errorf("MatchedRuleIndex = %d, want 0", dec.MatchedRuleIndex)
	}
}

// TestEvaluate_ContextScoped_UnknownDepartment_Denies — department not in any rule.
func TestEvaluate_ContextScoped_UnknownDepartment_Denies(t *testing.T) {
	s := NewService(&memRepo{policy: financeContextPolicy()})
	dec, _ := s.Evaluate(context.Background(), "", "admin", "legal", "standard", "openai", "gpt-4")
	if dec.Kind != DecisionDeny {
		t.Errorf("unknown department: got %+v, want Deny", dec)
	}
	if dec.Code != CodeUnknownDepartment {
		t.Errorf("code = %q, want %q", dec.Code, CodeUnknownDepartment)
	}
}

// TestEvaluate_ContextScoped_EmptyDepartment_Denies — missing JWT department.
func TestEvaluate_ContextScoped_EmptyDepartment_Denies(t *testing.T) {
	s := NewService(&memRepo{policy: financeContextPolicy()})
	dec, _ := s.Evaluate(context.Background(), "", "analyst", "", "standard", "openai", "gpt-4")
	if dec.Kind != DecisionDeny || dec.Code != CodeUnknownDepartment {
		t.Errorf("empty department: got %+v, want Deny/unknown_department", dec)
	}
}

// TestEvaluate_ContextScoped_WrongSensitivity_SensitivityDenied — dept+role matched,
// but sensitivity not permitted. Must return sensitivity_denied (not unknown_department).
func TestEvaluate_ContextScoped_WrongSensitivity_SensitivityDenied(t *testing.T) {
	s := NewService(&memRepo{policy: financeContextPolicy()})
	// finance/analyst allows confidential+standard for gpt-4, but restricted is not in the list.
	dec, _ := s.Evaluate(context.Background(), "", "analyst", "finance", "restricted", "openai", "gpt-4")
	if dec.Kind != DecisionDeny {
		t.Errorf("wrong sensitivity: got %+v, want Deny", dec)
	}
	if dec.Code != CodeSensitivityDenied {
		t.Errorf("code = %q, want %q", dec.Code, CodeSensitivityDenied)
	}
}

// TestEvaluate_ContextScoped_UnknownSensitivity_Denies — "unknown" sensitivity
// (missing header, fail-restrictive default) is denied unless explicitly allowed.
func TestEvaluate_ContextScoped_UnknownSensitivity_Denies(t *testing.T) {
	s := NewService(&memRepo{policy: financeContextPolicy()})
	dec, _ := s.Evaluate(context.Background(), "", "analyst", "finance", "unknown", "openai", "gpt-4")
	if dec.Kind != DecisionDeny {
		t.Errorf("unknown sensitivity: got %+v, want Deny", dec)
	}
	if dec.Code != CodeSensitivityDenied {
		t.Errorf("code = %q, want %q", dec.Code, CodeSensitivityDenied)
	}
}

// TestEvaluate_ContextScoped_WildcardRole_AllowsAnyRole — rule with Role="*"
// matches any role if dept+sensitivity match.
func TestEvaluate_ContextScoped_WildcardRole_AllowsAnyRole(t *testing.T) {
	s := NewService(&memRepo{policy: financeContextPolicy()})
	// finance / any role / standard → ollama/llama3
	dec, _ := s.Evaluate(context.Background(), "", "manager", "finance", "standard", "ollama", "llama3")
	if dec.Kind != DecisionAllow {
		t.Errorf("wildcard role: got %+v, want Allow", dec)
	}
}

// TestEvaluate_ContextScoped_ProviderNotInMatchedRule_Denies — context matches
// but requested provider not in the rule's allowlist.
func TestEvaluate_ContextScoped_ProviderNotInMatchedRule_Denies(t *testing.T) {
	s := NewService(&memRepo{policy: financeContextPolicy()})
	// finance/analyst/confidential matches rule[0] but rule[0] only allows openai.
	dec, _ := s.Evaluate(context.Background(), "", "analyst", "finance", "confidential", "gemini", "gemini-pro")
	if dec.Kind != DecisionDeny {
		t.Errorf("wrong provider: got %+v, want Deny", dec)
	}
	if dec.Code != CodeUnknownProvider {
		t.Errorf("code = %q, want %q", dec.Code, CodeUnknownProvider)
	}
}

// TestEvaluate_ContextScoped_StrictModesUnchanged — allowlist_strict ignores
// department and sensitivity (backward compat for G1/G2).
func TestEvaluate_ContextScoped_StrictModesUnchanged(t *testing.T) {
	s := NewService(&memRepo{policy: &Policy{
		ID: "p-strict", Mode: ModeAllowlistStrict, IsActive: true,
		Rules: []ProviderRule{{Provider: "openai", Models: []string{"gpt-4"}}},
	}})
	// dept and sensitivity are ignored in strict mode.
	dec, _ := s.Evaluate(context.Background(), "", "admin", "finance", "restricted", "openai", "gpt-4")
	if dec.Kind != DecisionAllow {
		t.Errorf("strict mode: dept/sensitivity must be ignored, got %+v", dec)
	}
}

// TestUpsert_ContextScoped_EmptyRules_Rejected — empty context_rules → ValidationError.
func TestUpsert_ContextScoped_EmptyRules_Rejected(t *testing.T) {
	s := NewService(&memRepo{})
	_, err := s.Upsert(context.Background(), &Policy{
		Mode:         ModeContextScoped,
		ContextRules: nil,
	}, "admin", "")
	if err == nil {
		t.Fatal("expected ValidationError for empty context_rules, got nil")
	}
	var valErr *ValidationError
	if !errors.As(err, &valErr) {
		t.Errorf("expected *ValidationError, got %T: %v", err, err)
	}
}

// TestUpsert_ContextScoped_EmptyRulesPerContext_Rejected — a context rule with
// no provider rules should be rejected (it silently denies all providers).
func TestUpsert_ContextScoped_EmptyRulesPerContext_Rejected(t *testing.T) {
	s := NewService(&memRepo{})
	_, err := s.Upsert(context.Background(), &Policy{
		Mode: ModeContextScoped,
		ContextRules: []ContextRule{
			{Department: "finance", Rules: nil}, // missing Rules
		},
	}, "admin", "")
	if err == nil {
		t.Fatal("expected ValidationError for empty context rule Rules, got nil")
	}
	var valErr *ValidationError
	if !errors.As(err, &valErr) {
		t.Errorf("expected *ValidationError, got %T: %v", err, err)
	}
}

// TestUpsert_ContextScoped_InvalidSensitivity_Rejected — unknown sensitivity enum.
func TestUpsert_ContextScoped_InvalidSensitivity_Rejected(t *testing.T) {
	s := NewService(&memRepo{})
	_, err := s.Upsert(context.Background(), &Policy{
		Mode: ModeContextScoped,
		ContextRules: []ContextRule{
			{
				Department:  "finance",
				Sensitivity: []SensitivityLevel{"top-secret"}, // invalid
				Rules:       []ProviderRule{{Provider: "openai", Models: []string{"gpt-4"}}},
			},
		},
	}, "admin", "")
	if err == nil {
		t.Fatal("expected ValidationError for invalid sensitivity, got nil")
	}
	var valErr *ValidationError
	if !errors.As(err, &valErr) {
		t.Errorf("expected *ValidationError, got %T: %v", err, err)
	}
}
