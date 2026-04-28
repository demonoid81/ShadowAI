# bd-ShadowAI-9ch — cleanup stale W7/W8/BYOK control gaps

## Контекст

После закрытия W7, W8, BYOK2 и BYOK2.1 часть customer-facing документов всё ещё описывала закрытые controls как roadmap/residual gaps. Это создаёт риск неверного ответа в security questionnaire: продукт выглядит слабее фактического состояния, а некоторые формулировки противоречат коду.

CASS недоступен: `cass health` вернул `index stale`. Источники истины: git history, bd, фактические документы и закрытые коммиты W7/W8/BYOK.

## Размышления

Рассмотрены варианты:

- оставить документы как conservative wording;
- переписать всё в optimistic sales wording;
- точечно заменить stale gaps на implemented/operational caveats.

Принято решение: точечная правка. Документы не должны переобещать certification или full BYOK для всех data classes, но закрытые W7/W8 controls больше нельзя называть roadmap gaps.

Альтернатива “sales wording” отклонена: SAML, external pen test, non-audit BYOK classes и legal-hold selector privacy остаются реальными residual gaps.

## План реализации

1. Обновить `production-hardening.md`: global admin BYOK caveat, known limits table, malformed table после BYOK example.
2. Обновить `soc2-iso-control-mapping.md`: W7/W8 controls как implemented, residual gaps как operator-owned execution/configuration.
3. Обновить roadmap: W7 evidence operations marked completed; remove stale current item.
4. Добавить examples.
5. Проверить stale phrases через `rg`, `git diff --check`.

## Roadmap

### v1

- Documentation truth cleanup for W7/W8/BYOK.

### v2+

- Separate formal BCP/security policy docs.
- SAML implementation only after customer-specific requirement.
- External assessor report after real pen test.
