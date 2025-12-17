#!/bin/bash
# Test script for subagent collaboration system

echo "🧪 Testing Claude Code Subagent Collaboration System"
echo "=================================================="

# Check all required files exist
FILES=(
    ".claude/agents.json"
    ".claude/agents/roles/architect.md"
    ".claude/agents/roles/backend-dev.md"
    ".claude/agents/roles/frontend-dev.md"
    ".claude/agents/roles/mobile-dev.md"
    ".claude/agents/roles/requirements-analyst.md"
    ".claude/agents/roles/test-engineer.md"
    ".claude/agents/roles/devops-engineer.md"
    ".claude/agents/workflows/feature-development.md"
    ".claude/agents/workflows/bug-fix.md"
    ".claude/agents/workflows/architecture-review.md"
    ".claude/agents.json"
    "CLAUDE.md"
    ".claude/commands/cooperate.md"
)

echo "🔍 Checking required files..."
MISSING=false
for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file"
    else
        echo "❌ $file (missing)"
        MISSING=true
    fi
done

echo ""
echo "📋 Checking YAML front matter format..."
for agent in architect backend-dev frontend-dev mobile-dev requirements-analyst test-engineer devops-engineer; do
    file=".claude/agents/roles/${agent}.md"
    if [ -f "$file" ]; then
        has_front_matter=$(grep -c "^---$" "$file")
        if [ "$has_front_matter" -ge 2 ]; then
            echo "✅ $agent - Has correct YAML front matter"
        else
            echo "⚠️  $agent - Missing front matter"
        fi
    fi
done

echo ""
if [ "$MISSING" = "true" ]; then
    echo "❌ System check failed - please fix missing files"
    exit 1
else
    echo "✅ All checks passed! System ready for auto-collaboration"
    echo ""
    echo "🚀 Commands you can use:"
    echo "   /feature \"name\" \"description\" - Full feature lifecycle"
    echo "   /fix \"bug description\" - Auto-bug resolution"
    echo "   /architecture topic - Design review"
    echo "   /task \"description\" - Smart task assignment"
    echo ""
    echo "📖 See CLAUDE.md for full collaboration guide"
fi