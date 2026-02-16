---
name: skill-reviewer
description: >
  Review and score skills for quality, correctness, and effectiveness. Use this skill
  whenever you need to evaluate an existing skill, audit a skill before deployment, check
  a skill for bugs or dead code, or score a skill's quality on a standardized rubric. Also
  use it when someone asks "is this skill any good?", "review my skill", "rate this skill",
  "what's wrong with this skill", or "how can I improve this skill". This skill provides
  both automated static analysis (dead code, unused imports, frontmatter validation) and a
  structured rubric for subjective evaluation (triggering quality, conciseness, writing
  style). The output is a scored report with concrete, prioritized fixes. Use this skill
  even for quick gut-checks — a fast review catches bugs that cost hours to debug later.
---

# Skill Reviewer

Evaluate any skill against a standardized quality rubric. Produces a scored report
with concrete fixes, ordered by impact. Combines automated static analysis with
structured subjective review.

## Review Workflow

### Step 1: Automated Analysis

Run the static analysis script against the skill directory:

```bash
python3 <skill-path>/scripts/analyze.py /path/to/skill --format text
```

Use `--format json` if you need structured output for further processing.

This catches mechanical issues automatically: missing frontmatter, dead imports,
unused variables, third-party dependencies, structural problems, misplaced top-level
files/directories, and line counts.
Start here because these findings are objective — they're either present or not.

### Step 2: Read the Rubric

Read `references/rubric.md` for the full scoring criteria. The rubric covers eight
dimensions, each with a 1-10 scale and specific criteria per score band:

| Dimension | Weight | What It Measures |
|-----------|--------|------------------|
| Triggering & Description | 1.5x | Would the skill activate when it should? |
| Conciseness | 1.0x | Does every line earn its place? |
| Why Explanation | 1.0x | Are instructions motivated, not just commanded? |
| Progressive Disclosure | 1.0x | Is info at the right loading level? |
| Script Quality | 1.5x | Do bundled scripts actually work correctly? |
| Separation of Concerns | 1.0x | Does the skill have a single clear job? |
| Generality | 1.0x | Would it work beyond the test cases? |
| Writing Style | 0.5x | Is it scannable, imperative, well-structured? |

Triggering and Script Quality carry 1.5x weight because they're the two most common
failure modes — skills that don't fire, and scripts that produce wrong results.

### Step 3: Manual Investigation

With the rubric in mind, investigate the skill:

1. **Read SKILL.md** — evaluate description, body structure, style
2. **Read each bundled script** — look for bugs, dead code, edge cases
3. **Cross-reference claims vs. behavior** — if SKILL.md says "supports X", verify
   the script actually handles X. This is where the most damaging bugs hide.
4. **Test edge cases** — run scripts with tricky inputs, boundary conditions,
   unusual phrasings. Think about what a real user would actually type.
5. **Check what's missing** — are there limitations that aren't documented?
   Patterns that should work but don't?
6. **Check folder conventions** — if reusable resources are at the skill root,
   propose creating `scripts/`, `references/`, and/or `assets/` (as needed) and
   moving files into those folders.

### Step 4: Score and Report

Score each dimension, then compute the weighted overall:

```
overall = (triggering×1.5 + conciseness×1.0 + why×1.0 + disclosure×1.0
         + scripts×1.5 + separation×1.0 + generality×1.0 + style×0.5) / 8.5
```

Present the report with this structure:

1. **Static analysis** — output from analyze.py
2. **Dimension scores** — score, evidence, specific issues per dimension
3. **Overall score** — weighted average out of 10
4. **Fix list** organized by priority:
   - **Must fix**: bugs, broken features, misleading docs
   - **Should fix**: dead code, documentation gaps, missing edge cases, and
     structure cleanup (create `scripts/` / `references/` / `assets/` when
     needed and move misplaced files)
   - **Nice to have**: style improvements, coverage expansion

## What Makes a Good Review

A good skill review is honest and specific. Avoid vague praise ("looks good") or
vague criticism ("needs work"). Every finding should point to a specific line, file,
or behavior, and every fix should be concrete enough that someone could implement it
without asking follow-up questions.

The goal isn't to be harsh — it's to catch the things that would cause real problems
when the skill is used at scale. A bug in a script that's called thousands of times
will burn thousands of tool calls producing wrong results. An undertriggered description
means the skill sits unused while the model fumbles through the task manually. These
are the high-impact findings worth surfacing.

When reviewing script correctness, actually run the scripts. Don't just read the code
and guess — execute it with realistic inputs and edge cases. The "in N business days"
bug pattern (where a regex can't match multi-word units because `\w` doesn't cross
spaces) is the kind of thing that looks fine on a read-through but fails immediately
when tested.
