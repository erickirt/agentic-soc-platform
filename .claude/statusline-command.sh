#!/bin/bash
# Claude Code statusline: shows all available info except rate limits.
# Uses ANSI 256-color codes for visual distinction.

input=$(cat)

# Color definitions (256-color)
SEP="\033[38;5;240m"     # dim gray separator
RST="\033[0m"            # reset
C_MODEL="\033[38;5;75m"  # bright cyan
C_DIR="\033[38;5;156m"   # light green
C_GIT="\033[38;5;140m"   # purple
C_CTX="\033[38;5;229m"   # light yellow
C_CTX_HIGH="\033[38;5;203m" # red for high usage
C_INFO="\033[38;5;180m"  # tan
C_TAG="\033[38;5;109m"   # teal

# Extract fields
model=$(echo "$input" | jq -r '.model.display_name // empty')
session_name=$(echo "$input" | jq -r '.session_name // empty')
cwd=$(echo "$input" | jq -r '.workspace.current_dir // empty')
project_dir=$(echo "$input" | jq -r '.workspace.project_dir // empty')
added_count=$(echo "$input" | jq -r '.workspace.added_dirs | length // 0')
git_worktree=$(echo "$input" | jq -r '.workspace.git_worktree // empty')
style=$(echo "$input" | jq -r '.output_style.name // empty')
version=$(echo "$input" | jq -r '.version // empty')
ctx_used=$(echo "$input" | jq -r '.context_window.used_percentage // empty')
effort=$(echo "$input" | jq -r '.effort.level // empty')
thinking=$(echo "$input" | jq -r '.thinking.enabled // false')
vim_mode=$(echo "$input" | jq -r '.vim.mode // empty')
agent_name=$(echo "$input" | jq -r '.agent.name // empty')
agent_type=$(echo "$input" | jq -r '.agent.type // empty')
wt_name=$(echo "$input" | jq -r '.worktree.name // empty')
wt_branch=$(echo "$input" | jq -r '.worktree.branch // empty')

# Separator: space + dim pipe + space
sep=" ${SEP}│${RST} "

parts=()

# Model (bright cyan)
[ -n "$model" ] && parts+=("${C_MODEL}${model}${RST}")

# Session name
[ -n "$session_name" ] && parts+=("${C_TAG}/${session_name}${RST}")

# Directory (light green)
if [ -n "$cwd" ]; then
  dir_display=$(basename "$cwd")
  parts+=("${C_DIR}${dir_display}${RST}")
fi

# Git status (purple)
if [ -n "$cwd" ] && [ -d "$cwd/.git" ]; then
  git_branch=$(git --no-optional-locks -C "$cwd" branch --show-current 2>/dev/null)
  if [ -n "$git_branch" ]; then
    git_status=$(git --no-optional-locks -C "$cwd" status --porcelain 2>/dev/null)
    if [ -n "$git_status" ]; then
      git_indicator="*"
    else
      git_indicator=""
    fi
    parts+=("${C_GIT}git:${git_branch}${git_indicator}${RST}")
  fi
fi

# Context usage (yellow, red if >80%)
if [ -n "$ctx_used" ]; then
  ctx_int=$(printf '%.0f' "$ctx_used")
  if [ "$ctx_int" -gt 80 ]; then
    parts+=("${C_CTX_HIGH}ctx:${ctx_int}%%${RST}")
  else
    parts+=("${C_CTX}ctx:${ctx_int}%%${RST}")
  fi
fi

# Effort (tan)
[ -n "$effort" ] && parts+=("${C_INFO}effort:${effort}${RST}")

# Thinking (tan)
[ "$thinking" = "true" ] && parts+=("${C_INFO}thinking${RST}")

# Vim mode (compact)
if [ -n "$vim_mode" ]; then
  case "$vim_mode" in
    "INSERT")      parts+=("${C_TAG}vim:I${RST}")  ;;
    "NORMAL")      parts+=("${C_TAG}vim:N${RST}")  ;;
    "VISUAL")      parts+=("${C_TAG}vim:V${RST}")  ;;
    "VISUAL LINE") parts+=("${C_TAG}vim:VL${RST}") ;;
    *)             parts+=("${C_TAG}vim:${vim_mode}${RST}") ;;
  esac
fi

# Agent (teal)
if [ -n "$agent_name" ]; then
  [ -n "$agent_type" ] && parts+=("${C_TAG}agent:${agent_name}(${agent_type})${RST}") || parts+=("${C_TAG}agent:${agent_name}${RST}")
fi

# Worktree
if [ -n "$wt_name" ]; then
  [ -n "$wt_branch" ] && parts+=("${C_INFO}wt:${wt_name}(${wt_branch})${RST}") || parts+=("${C_INFO}wt:${wt_name}${RST}")
fi

# Linked worktree
[ -n "$git_worktree" ] && parts+=("${C_INFO}linked:${git_worktree}${RST}")

# Added dirs count
[ "$added_count" -gt 0 ] && parts+=("${C_INFO}+${added_count}dirs${RST}")

# Project dir (only if different from cwd)
if [ -n "$project_dir" ] && [ "$project_dir" != "$cwd" ]; then
  proj_base=$(basename "$project_dir")
  parts+=("${C_INFO}project:${proj_base}${RST}")
fi

# Output style
[ -n "$style" ] && parts+=("${C_INFO}${style}${RST}")

# Version
[ -n "$version" ] && parts+=("${C_INFO}v${version}${RST}")

# Manual join with separator
first=true
for part in "${parts[@]}"; do
  if $first; then
    printf '%b' "$part"
    first=false
  else
    printf '%b' "${sep}${part}"
  fi
done
echo
