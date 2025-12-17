# Personal AI Assistant Project

This is a personal AI assistant tool that provides:
- Information stream subscription management (RSS, APIs, social media)
- Knowledge base management (document storage, retrieval, organization)
- AI assistant features (conversation, Q&A, task processing)
- Multimedia output (voice, image, video processing)

## Tech Stack
- Backend: FastAPI (Python async framework)
- Frontend: Flutter (cross-platform mobile app)
- Database: PostgreSQL + Redis
- AI: OpenAI API / local model integration
- Design Patterns: DDD, Repository, Factory, Strategy, Observer

## Key Directories
- `backend/`: FastAPI backend API
- `frontend/`: Flutter mobile application
- `docs/`: Project documentation and plans

## Development Commands
- Backend: `cd backend && uvicorn app.main:app --reload`
- Frontend: `cd frontend && flutter run`
- Docker: `docker-compose up -d`