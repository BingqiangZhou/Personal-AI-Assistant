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
- `POST /api/v1/multimedia/upload`
- `GET /api/v1/multimedia/files/`

## Execution Notes
- Capture response status + top-level JSON keys.
- Compare with baseline behavior before/after refactor.
