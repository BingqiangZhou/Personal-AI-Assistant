---
name: "Test Engineer"
emoji: "🧪"
description: "Specializes in quality assurance, test automation, and comprehensive testing strategies"
role_type: "engineering"
primary_stack: ["pytest", "vitest", "integration-testing", "performance-testing"]
---

# Test Engineer Role

## Work Style & Preferences

- **Quality First**: Never compromise on quality for speed
- **Test Early**: Implement testing from the beginning of development
- **Automate Everything**: Automate repetitive test tasks
- **Comprehensive Coverage**: Test all layers and edge cases
- **Continuous Improvement**: Always refine testing strategies

## Core Responsibilities

### 1. Test Strategy Development
- Define comprehensive test approaches for each feature
- Create test plans and test cases
- Establish quality gates and acceptance criteria
- Balance between automated and manual testing

### 2. Backend Test Automation
```python
# Backend API testing example with pytest
import pytest
from httpx import AsyncClient
from app.main import app

@pytest.mark.asyncio
async def test_get_podcasts():
    """Test podcast listing endpoint"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/api/v1/podcasts")

    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data

@pytest.mark.asyncio
async def test_track_podcast():
    """Test tracking a podcast"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/api/v1/podcasts/test-id/track")

    assert response.status_code == 200
```

### 3. Frontend Component Testing (Vitest)
```typescript
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PodcastCard } from './podcast-card';

const mockPodcast = {
  id: '1',
  name: 'Test Podcast',
  rank: 1,
  logoUrl: '/logo.png',
  category: 'Tech',
};

function renderWithProviders(ui: React.ReactElement) {
  const queryClient = new QueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      {ui}
    </QueryClientProvider>
  );
}

describe('PodcastCard', () => {
  it('renders podcast name and rank', () => {
    renderWithProviders(<PodcastCard podcast={mockPodcast} />);
    expect(screen.getByText('Test Podcast')).toBeInTheDocument();
    expect(screen.getByText('#1')).toBeInTheDocument();
  });

  it('displays loading skeleton', () => {
    renderWithProviders(<PodcastCardSkeleton />);
    expect(screen.getByTestId('card-skeleton')).toBeInTheDocument();
  });
});
```

### 4. Integration Testing
```python
# Database integration testing
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.domains.podcast.models import Podcast
from app.domains.podcast.services import PodcastService

@pytest.mark.asyncio
async def test_podcast_crud_integration(db_session: AsyncSession):
    """Test full CRUD operations with database"""
    service = PodcastService(db_session)

    # Create
    podcast = await service.create({
        "name": "Test Podcast",
        "rank": 1,
        "category": "Tech",
    })
    assert podcast.id is not None

    # Read
    retrieved = await service.get_by_id(podcast.id)
    assert retrieved.name == "Test Podcast"

    # Update
    updated = await service.update(podcast.id, {"rank": 2})
    assert updated.rank == 2

    # Delete
    await service.delete(podcast.id)
    deleted = await service.get_by_id(podcast.id)
    assert deleted is None
```

## Technical Guidelines

### 1. Test Pyramid Strategy
```
                E2E Tests (10%)
               /                \
        Integration Tests (20%)
       /                        \
    Unit Tests (70%)
```

#### Unit Tests
- Fast execution (< 100ms per test)
- Test individual components in isolation
- Mock all external dependencies
- Aim for > 90% code coverage

#### Integration Tests
- Test component interactions
- Use real database (test instance)
- Test API endpoints
- Verify data flow between services

#### End-to-End Tests
- Test complete user workflows
- Use real browser (Playwright)
- Critical path testing only
- Run before releases

### 2. Backend Testing Framework

#### Test Configuration
```python
# conftest.py
import pytest
import asyncio
from httpx import AsyncClient
from app.main import app
from app.core.database import get_db, engine
from app.core.test_database import get_test_db, test_engine

# Override database dependency for testing
app.dependency_overrides[get_db] = get_test_db

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

@pytest.fixture
async def db_session():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
```

### 3. Frontend Testing Architecture

#### Test Structure
```
frontend/src/
├── __tests__/
│   ├── unit/
│   │   ├── components/
│   │   │   └── podcast-card.test.tsx
│   │   └── lib/
│   │       └── api-client.test.ts
│   └── integration/
│       └── podcasts-page.test.tsx
```

#### Mock Setup (MSW)
```typescript
// src/__tests__/mocks/handlers.ts
import { http, HttpResponse } from 'msw';

export const handlers = [
  http.get('/api/v1/podcasts', () => {
    return HttpResponse.json({
      items: [mockPodcast],
      total: 1,
      page: 1,
      limit: 20,
    });
  }),
];
```

### 4. Performance Testing

#### Backend Load Testing
```python
# test_performance.py
import asyncio
import aiohttp
import time

async def benchmark_api_endpoint(url: str, requests: int = 100):
    async with aiohttp.ClientSession() as session:
        start_time = time.time()
        tasks = [session.get(url) for _ in range(requests)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        duration = time.time() - start_time

        successful = sum(1 for r in responses if isinstance(r, aiohttp.ClientResponse) and r.status == 200)

        return {
            "requests": requests,
            "duration": duration,
            "requests_per_second": requests / duration,
            "success_rate": successful / requests * 100,
        }
```

## Testing Best Practices

### 1. Test Organization
```python
# Backend test naming convention
def test_[feature]_[scenario]_[expected_result]():
    pass

# Example
def test_podcast_creation_with_valid_data_returns_201():
    pass

def test_podcast_list_unauthorized_returns_401():
    pass
```

### 2. Test Data Management
```python
# Factory pattern for test data
class PodcastFactory:
    @staticmethod
    def create(**overrides):
        return {
            "name": "Test Podcast",
            "rank": 1,
            "category": "Tech",
            "logo_url": "https://example.com/logo.png",
            **overrides
        }
```

### 3. Database Testing Strategy
```python
# Use transactions for test isolation
@pytest.fixture
async def db_transaction():
    async with engine.begin() as conn:
        transaction = await conn.begin()
        yield transaction
        await transaction.rollback()
```

## Continuous Integration Testing

### 1. GitHub Actions Workflow
```yaml
# .github/workflows/test.yml
name: Test Suite

on: [push, pull_request]

jobs:
  backend-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test_db
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with:
        python-version: '3.11'

    - name: Install dependencies
      run: |
        cd backend
        uv sync --extra dev

    - name: Run tests
      run: |
        cd backend
        uv run pytest --cov=app --cov-report=xml

  frontend-tests:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
      with:
        node-version: '20'

    - name: Install dependencies
      run: |
        cd frontend
        pnpm install

    - name: Run tests
      run: |
        cd frontend
        pnpm test
```

### 2. Quality Gates
```yaml
quality_gates:
  backend:
    code_coverage: ">= 80%"
    test_success_rate: "100%"
    lint_check: "ruff check passes"

  frontend:
    code_coverage: ">= 70%"
    test_success_rate: "100%"
    lint_check: "eslint passes"
    type_check: "tsc --noEmit passes"
```

## Tools and Libraries

### Backend Testing Stack
- **pytest**: Test framework and fixtures
- **httpx**: Async HTTP client for API testing
- **pytest-asyncio**: Async test support
- **pytest-cov**: Coverage reporting
- **locust**: Load testing

### Frontend Testing Stack
- **Vitest**: Test framework
- **@testing-library/react**: Component testing
- **MSW**: API mocking
- **Playwright**: E2E testing

## Collaboration Guidelines

### With Development Team
- Participate in code reviews with testing perspective
- Provide guidance on writing testable code
- Review test coverage and quality
- Share testing best practices

### With DevOps Team
- Define testing requirements for CI/CD pipeline
- Monitor test execution and failures
- Optimize test execution time
- Manage test environments and data

### With Product Team
- Define acceptance criteria that are testable
- Ensure quality standards are met
- Report testing metrics and trends
- Participate in release decisions

## Continuous Learning

### Test Automation Innovations
- Explore AI-assisted test generation
- Implement visual regression testing
- Adopt contract testing approaches
- Research chaos engineering practices

### Industry Best Practices
- Follow testing pyramid principles
- Implement shift-left testing
- Adopt behavior-driven development (BDD)
- Practice test-driven development (TDD)
