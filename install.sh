#!/bin/sh
# agentbin installer — installs the agentbin skill for every supported
# coding agent found on this machine. Safe to re-run (idempotent).
#   curl -fsSL https://agentbin.sh/install | sh
set -e

BASE="${AGENTBIN_URL:-https://agentbin.sh}"
installed=""

for skills_dir in "$HOME/.claude/skills" "$HOME/.codex/skills" "$HOME/.pi/agent/skills"; do
  agent_home=$(dirname "$skills_dir")
  case "$skills_dir" in
    */agent/skills) agent_home=$(dirname "$agent_home") ;;
  esac
  [ -d "$agent_home" ] || continue
  mkdir -p "$skills_dir/agentbin"
  curl -fsSL "$BASE/skill" -o "$skills_dir/agentbin/SKILL.md"
  installed="$installed $(basename "$agent_home" | tr -d .)"
done

if [ -z "$installed" ]; then
  echo "agentbin: no supported agent found (looked for ~/.claude, ~/.codex, ~/.pi)"
  echo "manual install for other agents:"
  echo "  curl -fsSL $BASE/skill >> AGENTS.md"
  exit 1
fi

echo "agentbin: skill installed for:$installed"
echo
echo "usage:"
echo "  1. after any agent response, type: /agentbin"
echo "  2. send the link it prints to a reviewer"
echo "  3. paste the link back into the session to fetch feedback"
