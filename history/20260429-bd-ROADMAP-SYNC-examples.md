# ShadowAI-de2 / ROADMAP-SYNC — примеры

## Happy path 1: оператор ищет Operations readiness

Вход: оператор читает roadmap после OPS4.

Ожидание: он видит, что OPS2-OPS4 закрыты: есть backend status API,
Prometheus-backed signals и last-success timestamps.

## Happy path 2: выбор следующего крупного трека

Вход: product/security stakeholder спрашивает, что делать дальше.

Ожидание: roadmap предлагает BYOK3 как следующий product/security track и SEC3
как business/external-assessment track.

## Edge case 1: не выбран customer KMS requirement

Вход: нет явного customer requirement на DEK epochs.

Ожидание: BYOK3 остаётся recommended product/security option, но не
маскируется как уже реализованная capability.

## Edge case 2: нужен procurement package

Вход: sales/security review требует independent assessment.

Ожидание: roadmap указывает SEC3 как альтернативный следующий трек.

## Failure case: stale roadmap

Вход: roadmap не отражает OPS2-OPS4.

Ожидание: это считается failure mode: future planning начинает повторно
создавать уже закрытые операции или игнорировать оставшиеся v2+ gaps.
