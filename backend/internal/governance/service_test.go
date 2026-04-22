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

func (m *memRepo) GetActive(ctx context.Context) (*Policy, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.policy, nil
}

func (m *memRepo) Upsert(ctx context.Context, p *Policy, actor string) (*Policy, error) {
	m.policy = p
	return p, nil
}

// TestEvaluate_NilService_AllowsAll — безопасная дефолт-DI для dev/tests
// деплоев без governance: nil Service возвращает Allow без чтения repo.
// Важно: nil-safe call через метод-receiver-pattern.
func TestEvaluate_NilService_AllowsAll(t *testing.T) {
	var s *Service // nil
	dec, err := s.Evaluate(context.Background(), "openai", "gpt-4")
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
	dec, err := s.Evaluate(context.Background(), "openai", "gpt-4")
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
	dec, err := s.Evaluate(context.Background(), "anthropic", "claude-3-opus")
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
	dec, _ := s.Evaluate(context.Background(), "openai", "gpt-4")
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
	dec, _ := s.Evaluate(context.Background(), "gemini", "gemini-pro")
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
	dec, _ := s.Evaluate(context.Background(), "openai", "gpt-4")
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
	dec, _ := s.Evaluate(context.Background(), "openai", "gpt-4")
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
	dec, _ := s.Evaluate(context.Background(), "openai", "gpt-4")
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
	dec, _ := s.Evaluate(context.Background(), "openai", "gpt-4")
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
	dec, err := s.Evaluate(context.Background(), "openai", "gpt-4")
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

// TestMode_IsValid — проверка валидатора для handler'а (admin UI
// может прислать typo или unknown tag).
func TestMode_IsValid(t *testing.T) {
	cases := []struct {
		in   Mode
		want bool
	}{
		{ModeDisabled, true},
		{ModeAllowlistStrict, true},
		{"", false},
		{"role_based", false}, // G2 mode, пока не реализован
		{"ALLOWLIST_STRICT", false}, // case-sensitive для хранимого значения
	}
	for _, c := range cases {
		if got := c.in.IsValid(); got != c.want {
			t.Errorf("IsValid(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
