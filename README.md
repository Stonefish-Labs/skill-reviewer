# Skill Reviewer

Review and score skills for quality, correctness, and effectiveness. Combines automated static analysis with a structured rubric for subjective evaluation.

## Overview

Evaluates any skill against a standardized quality rubric. Produces a scored report with concrete fixes, ordered by impact. Catches mechanical issues (dead code, unused imports, frontmatter validation) and assesses subjective dimensions (triggering quality, conciseness, writing style).

## Usage

1. Run the static analysis script against a skill directory:
   ```bash
   python3 skills/scripts/analyze.py /path/to/skill --format text
   ```

2. Read `skills/references/rubric.md` for scoring criteria across eight dimensions.

3. Score each dimension (1-10), compute weighted overall, and produce a fix list organized by priority (must fix, should fix, nice to have).

Trigger phrases: "review my skill", "rate this skill", "is this skill any good?", "what's wrong with this skill", "how can I improve this skill".

## License

MIT
