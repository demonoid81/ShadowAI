package proxy

import (
	"context"
	"encoding/json"

	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/firewall"
)

// shadowCtxKey — ключ для хранения request-scoped агрегата
// shadow-решений. Prefer context-value hand-off перед ручным прокидыванием
// aggregatedShadow через 28 мест записи audit_logs: минимизирует изменения
// в handler.go и не увеличивает arity helper'ов.
type shadowCtxKey struct{}

// shadowSlot — mutable накопитель, привязанный к request-context.
// Используется через *pointer, чтобы appendShadowDecisions мог мутировать
// slice, не теряя доступа для последующих read'ов из того же context.
type shadowSlot struct {
	decisions []firewall.ShadowDecision
}

// withShadowSlot возвращает новый context с чистым slot'ом. Вызывается
// в начале каждого handler, который делает firewall.Inspect*.
func withShadowSlot(ctx context.Context) context.Context {
	return context.WithValue(ctx, shadowCtxKey{}, &shadowSlot{})
}

// appendShadowDecisions добавляет решения shadow-инспекторов из firewall
// decision в request-scoped накопитель. Безопасно вызывается, даже если
// context не содержит slot (в этом случае — no-op).
func appendShadowDecisions(ctx context.Context, decs []firewall.ShadowDecision) {
	if len(decs) == 0 {
		return
	}
	slot, ok := ctx.Value(shadowCtxKey{}).(*shadowSlot)
	if !ok || slot == nil {
		return
	}
	slot.decisions = append(slot.decisions, decs...)
}

// encodeShadowFromCtx возвращает сериализованный JSONB-массив или пустую
// строку (→ NULL в Postgres), если shadow-решений не было. Errors от
// json.Marshal в этом сценарии невозможны (фиксированная схема),
// но на всякий случай fall back на пустую строку: audit запись важнее
// целостности shadow-данных.
func encodeShadowFromCtx(ctx context.Context) string {
	slot, ok := ctx.Value(shadowCtxKey{}).(*shadowSlot)
	if !ok || slot == nil || len(slot.decisions) == 0 {
		return ""
	}
	b, err := json.Marshal(slot.decisions)
	if err != nil {
		return ""
	}
	return string(b)
}

// auditLog обёртка над auditSvc.Log, которая подтягивает shadow-решения
// из request-scoped context и присваивает их log.ShadowDecisionsJSON
// перед Insert. Используется вместо прямого h.auditSvc.Log(log) во всех
// 20+ call-site'ах handler.go — это единая точка wiring'а shadow → audit.
//
// Если context не содержит slot'а (например, в TestProvider flow, где
// firewall pipeline не запускается), ShadowDecisionsJSON останется "".
func (h *Handler) auditLog(ctx context.Context, log *domain.AuditLog) {
	if h.auditSvc == nil {
		return
	}
	log.ShadowDecisionsJSON = encodeShadowFromCtx(ctx)
	h.auditSvc.Log(log)
}
