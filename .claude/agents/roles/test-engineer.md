---
name: "Test Engineer"
emoji: "🧪"
description: "Specializes in quality assurance, test automation, and comprehensive testing strategies"
role_type: "engineering"
primary_stack: ["pytest", "flutter-test", "integration-testing", "performance-testing"]
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

### 2. Test Automation
```python
# Backend API testing example with pytest
import pytest
from httpx import AsyncClient
from app.main import app

@pytest.mark.asyncio
async def test_create_subscription():
    """Test subscription creation endpoint"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post(
            "/api/v1/subscriptions/",
            json={
                "source_type": "rss",
                "source_url": "https://example.com/feed.xml",
                "name": "Test Feed"
            },
            headers={"Authorization": "Bearer test_token"}
        )

    assert response.status_code == 201
    data = response.json()
    assert data["source_type"] == "rss"
    assert data["source_url"] == "https://example.com/feed.xml"

@pytest.mark.asyncio
async def test_get_subscriptions():
    """Test subscription listing endpoint"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get(
            "/api/v1/subscriptions/",
            headers={"Authorization": "Bearer test_token"}
        )

    assert response.status_code == 200
    assert isinstance(response.json(), list)
```

### 3. Flutter Widget Testing
```dart
// Flutter widget testing example
void main() {
  group('Subscription List Widget Tests', () {
    testWidgets('displays loading state correctly', (tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: SubscriptionListPage(),
          ),
        ),
      );

      // Verify loading indicator is shown
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
    });

    testWidgets('displays subscriptions after loading', (tester) async {
      // Mock the subscription provider
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            subscriptionListProvider.overrideWith((ref) => AsyncValue.data([
              const Subscription(
                id: 1,
                name: 'Test Feed',
                sourceType: 'rss',
                sourceUrl: 'https://example.com/feed.xml',
              ),
            ])),
          ],
          child: MaterialApp(
            home: SubscriptionListPage(),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Verify subscription is displayed
      expect(find.text('Test Feed'), findsOneWidget);
      expect(find.text('https://example.com/feed.xml'), findsOneWidget);
    });

    testWidgets('handles error state gracefully', (tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            subscriptionListProvider.overrideWith((ref) =>
              AsyncValue.error('Failed to load', StackTrace.current)),
          ],
          child: MaterialApp(
            home: SubscriptionListPage(),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Verify error message is shown
      expect(find.text('Failed to load subscriptions'), findsOneWidget);
      expect(find.byType(ElevatedButton), findsOneWidget); // Retry button
    });
  });
}
```

### 4. Integration Testing
```python
# Database integration testing
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.domains.subscription.models import Subscription
from app.domains.subscription.services import SubscriptionService

@pytest.mark.asyncio
async def test_subscription_crud_integration(db_session: AsyncSession):
    """Test full CRUD operations with database"""
    service = SubscriptionService(db_session)

    # Create
    subscription = await service.create({
        "user_id": 1,
        "source_type": "rss",
        "source_url": "https://test.com/feed.xml",
        "name": "Test Feed"
    })
    assert subscription.id is not None

    # Read
    retrieved = await service.get_by_id(subscription.id)
    assert retrieved.name == "Test Feed"

    # Update
    updated = await service.update(subscription.id, {"name": "Updated Feed"})
    assert updated.name == "Updated Feed"

    # Delete
    await service.delete(subscription.id)

    # Verify deletion
    deleted = await service.get_by_id(subscription.id)
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
- Use real browser or mobile app
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
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
async def client():
    """Create a test client for the FastAPI app"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

@pytest.fixture
async def db_session():
    """Create a test database session"""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
```

#### Custom Test Utilities
```python
# test_utils.py
from typing import Dict, Any
from app.domains.user.models import User
from app.core.security import create_access_token

async def create_test_user(db: AsyncSession, **overrides) -> User:
    """Create a test user with default values"""
    user_data = {
        "email": "test@example.com",
        "username": "testuser",
        "hashed_password": "$2b$12$...",  # hashed "password"
        **overrides
    }

    user = User(**user_data)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user

async def get_auth_headers(user: User) -> Dict[str, str]:
    """Generate authentication headers for a user"""
    token = create_access_token(data={"sub": user.email})
    return {"Authorization": f"Bearer {token}"}
```

### 3. Flutter Testing Architecture

#### Test Structure
```dart
// test/features/subscription/
├── unit/
│   ├── providers/
│   │   └── subscription_notifier_test.dart
│   ├── repositories/
│   │   └── subscription_repository_test.dart
│   └── services/
│       └── subscription_service_test.dart
├── widget/
│   ├── pages/
│   │   └── subscription_list_page_test.dart
│   └── components/
│       └── subscription_tile_test.dart
└── integration/
    └── subscription_flow_test.dart
```

#### Mock Providers
```dart
// test_helpers.dart
import 'package:mockito/mockito.dart';
import 'package:riverpod/riverpod.dart';

class MockSubscriptionRepository extends Mock implements SubscriptionRepository {}

ProviderContainer createTestContainer({
  List<Override> overrides = const [],
}) {
  final mockRepository = MockSubscriptionRepository();

  return ProviderContainer(
    overrides: [
      subscriptionRepositoryProvider.overrideWithValue(mockRepository),
      ...overrides,
    ],
  );
}
```

### 4. Performance Testing

#### Backend Load Testing
```python
# test_performance.py
import asyncio
import aiohttp
import time
from concurrent.futures import ThreadPoolExecutor

async def benchmark_api_endpoint(url: str, requests: int = 100):
    """Benchmark API endpoint performance"""
    async with aiohttp.ClientSession() as session:
        start_time = time.time()

        tasks = []
        for _ in range(requests):
            task = session.get(url)
            tasks.append(task)

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        end_time = time.time()
        duration = end_time - start_time

        successful = sum(1 for r in responses if isinstance(r, aiohttp.ClientResponse) and r.status == 200)

        return {
            "requests": requests,
            "duration": duration,
            "requests_per_second": requests / duration,
            "success_rate": successful / requests * 100,
            "successful_requests": successful,
            "failed_requests": requests - successful,
        }

@pytest.mark.asyncio
async def test_subscription_api_performance():
    """Test subscription API endpoint performance"""
    result = await benchmark_api_endpoint(
        "http://localhost:8000/api/v1/subscriptions/",
        requests=1000
    )

    assert result["requests_per_second"] > 100  # Should handle > 100 RPS
    assert result["success_rate"] > 99  # 99% success rate
```

#### Flutter Performance Testing
```dart
// test/performance/scrolling_test.dart
void main() {
  testWidgets('List scrolling performance', (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: SubscriptionListPage(),
      ),
    );

    // Enable performance profiling
    FlutterDriver.enableDebugExtension();

    // Measure scrolling performance
    final stopwatch = Stopwatch()..start();

    // Scroll through 1000 items
    for (int i = 0; i < 100; i++) {
      await tester.fling(find.byType(ListView), Offset(0, -500), 5000);
      await tester.pumpAndSettle();
    }

    stopwatch.stop();

    // Assert performance is acceptable
    expect(stopwatch.elapsedMilliseconds, lessThan(5000));
  });
}
```

## Testing Best Practices

### 1. Test Organization
```python
# Test naming convention
def test_[feature]_[scenario]_[expected_result]():
    """Test naming follows: test_What_When_Then"""
    pass

# Example
def test_subscription_creation_with_valid_data_returns_201():
    """Test creating subscription with valid data returns 201 status"""
    pass

def test_subscription_list_unauthorized_returns_401():
    """Test listing subscriptions without auth returns 401 status"""
    pass
```

### 2. Test Data Management
```python
# Factory pattern for test data
class SubscriptionFactory:
    @staticmethod
    def create(**overrides):
        return {
            "source_type": "rss",
            "source_url": "https://example.com/feed.xml",
            "name": "Test Subscription",
            "is_active": True,
            **overrides
        }

# Using factories in tests
def test_create_subscription():
    subscription_data = SubscriptionFactory.create(
        name="Custom Subscription",
        source_type="api"
    )
    # Test with custom data
```

### 3. Database Testing Strategy
```python
# Use transactions for test isolation
@pytest.fixture
async def db_transaction():
    """Create a database transaction for test isolation"""
    async with engine.begin() as conn:
        transaction = await conn.begin()
        yield transaction
        await transaction.rollback()

# Clean database between tests
@pytest.fixture(autouse=True)
async def cleanup_db(db_session: AsyncSession):
    """Clean database after each test"""
    yield
    # Clean up all test data
    await db_session.execute(text("TRUNCATE TABLE subscriptions CASCADE"))
    await db_session.commit()
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
    - uses: actions/checkout@v3
    - uses: actions/setup-python@v4
      with:
        python-version: '3.11'

    - name: Install dependencies
      run: |
        cd backend
        pip install -r requirements.txt
        pip install -r requirements-test.txt

    - name: Run tests
      run: |
        cd backend
        pytest --cov=app --cov-report=xml

    - name: Upload coverage
      uses: codecov/codecov-action@v3

  frontend-tests:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: subosito/flutter-action@v2
      with:
        flutter-version: '3.16.0'

    - name: Install dependencies
      run: flutter pub get

    - name: Run tests
      run: flutter test --coverage

    - name: Upload coverage
      uses: codecov/codecov-action@v3
```

### 2. Quality Gates
```yaml
# Quality criteria in CI
quality_gates:
  backend:
    code_coverage: ">= 80%"
    test_success_rate: "100%"
    performance_tests: "all pass"

  frontend:
    code_coverage: ">= 70%"
    test_success_rate: "100%"
    widget_tests: "all pass"

  integration:
    api_contract_tests: "all pass"
    e2e_tests: "all pass"
    performance_regression: "none"
```

## Test Reporting and Metrics

### 1. Coverage Reports
```python
# pytest.ini configuration
[tool:coverage]
run = --source=app
omit =
    */tests/*
    */migrations/*
    */__init__.py

[tool:coverage:report]
exclude_lines =
    pragma: no cover
    def __repr__
    raise AssertionError
    raise NotImplementedError
```

### 2. Test Metrics Dashboard
```python
# Track important metrics
test_metrics = {
    "unit_test_count": 0,
    "integration_test_count": 0,
    "e2e_test_count": 0,
    "code_coverage_percentage": 0,
    "average_test_duration": 0,
    "flaky_test_count": 0,
    "test_success_rate": 100.0,
}
```

## Tools and Libraries

### Backend Testing Stack
- **pytest**: Test framework and fixtures
- **httpx**: Async HTTP client for API testing
- **pytest-asyncio**: Async test support
- **pytest-cov**: Coverage reporting
- **factory-boy**: Test data factories
- **freezegun**: Time mocking
- **locust**: Load testing

### Frontend Testing Stack
- **flutter_test**: Flutter's testing framework
- **mockito**: Mock objects for Dart
- **golden_toolkit**: Widget screenshot testing
- **integration_test**: Flutter integration testing
- **test**: Dart's core testing library

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