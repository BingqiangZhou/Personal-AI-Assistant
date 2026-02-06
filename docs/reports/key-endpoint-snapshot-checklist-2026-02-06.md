# Key Endpoint Snapshot Checklist (2026-02-06)

Use this list for focused regression checks after backend architecture refactor.

## Auth
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`

## Subscription
- `GET /api/v1/subscriptions/`
- `POST /api/v1/subscriptions/`
- `DELETE /api/v1/subscriptions/{subscription_id}`

## Podcast
- `POST /api/v1/podcasts/subscriptions`
- `GET /api/v1/podcasts/subscriptions`
- `POST /api/v1/podcasts/subscriptions/bulk-delete`
- `GET /api/v1/podcasts/episodes`
- `GET /api/v1/podcasts/episodes/{episode_id}`
- `POST /api/v1/podcasts/episodes/{episode_id}/transcribe`
- `GET /api/v1/podcasts/transcriptions/{task_id}/status`
- `GET /api/v1/podcasts/episodes/{episode_id}/conversations`
- `POST /api/v1/podcasts/episodes/{episode_id}/conversations`

## Multimedia
- `POST /api/v1/multimedia/files/upload`
- `GET /api/v1/multimedia/files/`

## Execution Notes
- Capture response status + top-level JSON keys.
- Compare with baseline behavior before/after refactor.

## Snapshot Results (2026-02-06)
- `POST /api/v1/auth/register` -> `422`, keys: `detail, errors, type`
- `POST /api/v1/auth/login` -> `422`, keys: `detail, errors, type`
- `POST /api/v1/auth/refresh` -> `422`, keys: `detail, errors, type`
- `GET /api/v1/subscriptions/` -> `401`, keys: `detail`
- `POST /api/v1/subscriptions/` -> `401`, keys: `detail`
- `DELETE /api/v1/subscriptions/1` -> `401`, keys: `detail`
- `POST /api/v1/podcasts/subscriptions` -> `401`, keys: `detail`
- `GET /api/v1/podcasts/subscriptions` -> `401`, keys: `detail`
- `POST /api/v1/podcasts/subscriptions/bulk-delete` -> `401`, keys: `detail`
- `GET /api/v1/podcasts/episodes` -> `401`, keys: `detail`
- `GET /api/v1/podcasts/episodes/1` -> `401`, keys: `detail`
- `POST /api/v1/podcasts/episodes/1/transcribe` -> `401`, keys: `detail`
- `POST /api/v1/podcasts/episodes/1/transcribe/schedule` -> `401`, keys: `detail`
- `DELETE /api/v1/podcasts/episodes/1/transcription` -> `401`, keys: `detail`
- `GET /api/v1/podcasts/transcriptions/1/status` -> `401`, keys: `detail`
- `GET /api/v1/podcasts/episodes/1/conversations` -> `401`, keys: `detail`
- `POST /api/v1/podcasts/episodes/1/conversations` -> `401`, keys: `detail`
- `POST /api/v1/podcasts/subscriptions/1/check-new-episodes` -> `401`, keys: `detail`
- `GET /api/v1/multimedia/files/` -> `401`, keys: `detail`
- `POST /api/v1/multimedia/files/upload` -> `401`, keys: `detail`
