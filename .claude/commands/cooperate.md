# Cooperation Commands

## 🤖 Intelligent Agent Collaboration

When I receive these commands, I automatically orchestrate multiple specialized agents to work together seamlessly.

### Commands

### 🚀 /feature "name" "description"
**Start Full Feature Development**
- **What happens**: Requirements → Architecture → Backend → Frontend → Tests → Deploy
- **Example**: `/feature "api-rate-limiting" "Prevent API abuse by rate limiting"`
- **Auto-orchestrates**: All 7 agents in optimal sequence with parallel work
- **Output**: Production-ready feature with full documentation

### 🔧 /fix "description"
**Auto-Bug Triage & Resolution**
- **What happens**: Bug reproduction → Root cause → Fix → Test → Deploy
- **Example**: `/fix "Memory crash when processing 10k documents"`
- **Team**: Test Engineer + relevant Developer + DevOps
- **Output**: Fix deployed and monitored

### 🏛️ /architecture "topic"
**Architecture Review & Decision**
- **What happens**: Research → Analysis → Review → Decision → Documentation
- **Example**: `/architecture "Event-driven microservices for notifications"`
- **Team**: Architect Paths: Backend Dev → Test Engineer → DevOps
- **Output**: ADR document + implementation plan

### 🎯 /task "description"
**Smart Role Selection & Execution**
- **What happens**: Role analysis → Task assignment → Execution → Handoff
- **Example**: `/task "#342 - Add GraphQL API support"`
- **Auto-detects**: Required expertise and best agent
- **Output**: Complete task with recommendations

### 🤝 /collaborate "requirement"
**Adaptive Orchestration**
- **What happens**: Dynamic role determination → Optimized workflow → Coordinated execution
- **Example`: `/collaborate "Batch document processing with AI analysis"`
- **Adapts**: Roles and workflow based on complexity
- **Output**: Custom team implementation

### 📊 /status
**Team Progress Check**
- Shows all agents and current task status
- Points to task board and current blockers
- Suggests next steps

### 🔄 /handoff "role"
**Manual Context Transfer**
- Transfers current context to named role
- Includes all work-in-progress and notes
- Prepares handoff package

### Run Command Examples:
- ` /feature "auth-improvement" "OAuth2 flow security enhancement"`
- ` /fix "User login token refresh fails on 401"`
- ` /architecture "Redis-based session management"`
- ` /task "Update API docs to include new endpoints"`

### Success Criteria:
- Quality gates at every step
- All tests must pass before next agent
- Documentation complete with code
- Performance benchmarks established
- Deployment monitoring implemented
- Handoff includes full context

### Error Handling:
- Agent cannot complete task → Escalates to Architect
- Test failures → Returns to developer with details
- Integration issues → All-hands session
- Performance issues → Architect + DevOps review
- Security concerns → Immediate stakeholder notification