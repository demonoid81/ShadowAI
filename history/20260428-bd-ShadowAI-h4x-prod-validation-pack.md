# bd-ShadowAI-h4x — PROD1 deployment-specific production validation pack

## Контекст

Roadmap после WORM, tenant isolation, BYOK, evidence automation и compliance
cleanup фиксирует, что фундаментальные blockers закрыты. Следующий практический
шаг — доказать готовность конкретного production deployment, а не только
наличие generic runbooks.

CASS недоступен: `cass health` вернул `index stale`. Источники истины:
локальный roadmap, production hardening guide, runbooks и фактический код CLI.

## Цель

Добавить переносимый validation pack, который оператор запускает перед go-live
и архивирует как production readiness artifact. Пакет должен проверять:

- Helm render с production values;
- rollout deployment в target namespace;
- `/api/health` и `/api/ready`;
- offline evidence bundle verification;
- S3/Object Lock retention posture.

## Scope In

- `cmd/shadowai-prod-validate` CLI.
- JSON/table report и exit codes `0/1/2`.
- Unit tests без live cluster/S3.
- Build wiring: Makefile, CI, Dockerfile.
- Runbook `docs/runbooks/production-validation.md`.
- Roadmap/production docs links.

## Scope Out

- Реальный customer cluster access.
- Хранение или вывод секретов.
- Новый Helm CronJob.
- Замена smoke/integration tests.

## Размышления

Рассмотрены варианты:

- только runbook без кода;
- произвольный command-runner из YAML/JSON;
- built-in CLI checks с фиксированным набором команд.

Принято решение: built-in CLI checks. Это снижает риск выполнения произвольных
операторских команд из файла и делает отчёт воспроизводимым. Секреты остаются
в окружении underlying tools (`kubectl`, AWS SDK/CLI behavior, `audit-*` CLIs),
а `shadowai-prod-validate` не принимает их как flags.

Альтернатива “только runbook” отклонена: без machine-readable report задача
не даёт audit-grade artifact. Альтернатива “arbitrary command config” отклонена:
она удобнее, но хуже по безопасности и воспроизводимости.

## План реализации

1. Написать red tests для config error, success JSON, command failure, HTTP failure, output file.
2. Реализовать CLI model: options, check runner, report, output writer.
3. Подключить CLI к Makefile/CI/Dockerfile.
4. Добавить production validation runbook и ссылки.
5. Обновить roadmap.
6. Прогнать тесты, build-cli, diff checks.

## Roadmap

### v1

- Built-in production validation pack без live test dependency.

### v2+

- Optional signed validation report.
- Optional Kubernetes Job wrapper для запуска внутри cluster.
- Provider credential smoke request с безопасным synthetic prompt.
