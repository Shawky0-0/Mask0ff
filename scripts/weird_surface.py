#!/usr/bin/env python3
"""Score a candidate by ZDE-style semantic-route priority: weird-surface score + evidence confidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from duplicate_check import DEFAULT_CASES, compare, tokens  # noqa: E402

SEMANTIC_ROLES = {
    "RAW_DATA": ["raw", "input", "body", "parameter", "request", "query string"],
    "STORED_DATA": ["database", "db ", "stored", "persist", "cache", "queue", "message", "stream", "record", "row", "collection"],
    "METADATA": ["metadata", "filename", "branch", "title", "label", "name field", "header", "tag", "attribute", "property"],
    "PATH_COMPONENT": ["path", "directory", "file name", "filename", "url path", "route"],
    "FILESYSTEM_OBJECT": ["file", "upload", "attachment", "artifact", "archive", "zip", "tar"],
    "TEMPLATE_DATA": ["template", "render", "markdown", "html", "jinja", "handlebars"],
    "EXPRESSION": ["expression", "spel", "eval", "grok", "regex", "formula"],
    "CONFIGURATION": ["config", "yaml", "json", "toml", "ini", "setting", "flag", "env var", "environment variable"],
    "GENERATED_CONFIGURATION": ["generated", "synthesized", "auto-generated", "provisioned", "baked"],
    "COMMAND_ARGUMENT": ["command", "shell", "argument", "arg", "parameter to", "exec"],
    "MODULE_IDENTIFIER": ["module", "import", "plugin", "class name", "type name", "loader", "reflect"],
    "WORKFLOW_INSTRUCTION": ["workflow", "ci", "action", "pipeline", "job step", "script step"],
    "TOOL_ARGUMENT": ["tool", "function call", "mcp", "agent", "api call"],
    "BUILD_INSTRUCTION": ["build", "dockerfile", "makefile", "compile", "package"],
    "AUTHORIZATION_INPUT": ["permission", "role", "tenant", "acl", "allowlist", "policy"],
}

WSS_WEIGHTS = {
    "C": 0.18,
    "M": 0.15,
    "X": 0.12,
    "P": 0.11,
    "G": 0.10,
    "D": 0.10,
    "I": 0.08,
    "A": 0.07,
    "F": 0.05,
    "N": 0.04,
}

PRIVILEGE_WORDS = ["privileged", "admin", "root", "worker", "runner", "service account", "internal", "server-side", "background", "cron"]
DEFERRED_WORDS = ["async", "asynchronous", "queue", "worker", "job", "scheduled", "cron", "deferred", "eventual", "webhook", "retry", "second-order", "stored"]
INTERPRETER_WORDS = ["template", "eval", "exec", "shell", "expression", "loader", "class resolution", "instantiate", "interpreter", "renderer", "spel", "ssti", "rce"]
FALLBACK_WORDS = ["fallback", "default", "unknown type", "auto-detect", "autodetect", "legacy", "compat", "retry", "error handler", "recovery", "migration"]
LOW_ATTENTION_WORDS = ["scripts", "tools", "build", "packaging", "release", "migration", "converter", "adapter", "legacy", "compat", "import", "export", "backup", "restore", "sanitizer", "preview", "thumbnail", "generator"]
GRAMMAR_WORDS = ["grammar", "parser", "parse", "encoding", "decode", "escape", "quoting", "validator", "format", "serialize", "deserialize", "delimiter", "charset", "canonical"]
AUTH_BOUNDARY_WORDS = ["unauthenticated", "anonymous", "no auth", "missing auth", "wrong role", "wrong tenant", "any user", "attacker-controlled"]

NOVELTY_EXEMPT = {"eval", "exec", "shell", "rce", "sqli", "xss", "ssrf", "injection"}
EVIDENCE_GATES = ("A1", "T1", "H1", "B1", "P1", "C1", "R1", "E1", "X1", "I1", "V1", "J1", "D1")


# Keywords that must be matched at both edges even though they are long
# enough for the loose rule below. Each one is an abbreviation or a proper
# noun whose letters also start an unrelated ordinary English word:
#   eval    -> would otherwise fire on "evaluation" and "evaluated"
#   exec    -> would otherwise fire on "executive"
#   import  -> would otherwise fire on "important"
#   spel    -> would otherwise fire on "spelling"
#   reflect -> would otherwise fire on "reflected", "reflection" and
#              "reflective". Those are the ordinary words for a reflected XSS
#              and for CORS origin reflection. Neither loads a module, so the
#              loose form put MODULE_IDENTIFIER on plain XSS findings.
STRICT_KEYWORDS = {"eval", "exec", "import", "spel", "reflect"}

# Below this length a keyword is always matched at both edges. "tar" would
# otherwise fire on "target", "ci" on "cipher", "ini" on "initial".
MIN_LOOSE_LENGTH = 4

# Word endings a LOOSE keyword may carry, shared by all of them.
#
# Before this list existed a loose keyword could be followed by ANY run of
# letters or digits, because that open ended tail was the only thing making
# "exec" reach "executed" and "upload" reach "uploaded". The price was measured
# and it was high: 'path' fired on "pathological", 'tool' on "toolbar", 'flag'
# on "flagged", 'formula' on "formulated", 'html' on "htmlspecialchars",
# 'action' on "actionable", and 'no auth' on "no author". A plain stored XSS
# finding earned SIX transitions it had no claim to and scored 59.1 where 44.1
# is right.
#
# The insight that fixes it: the bad tails are not word endings at all.
#   path + "ological"  is not an ending of anything
#   tool + "bar"       is not an ending
#   upload + "ed"      IS an ordinary English ending
#   store + "d"        IS an ordinary English ending
# So the tail is bounded to a set of real endings instead of being open. This
# is not a stemmer and it does not need a dictionary. It is a short list of
# suffixes English actually uses, and everything outside it is refused.
#
# What is deliberately NOT in the list, and why, because each omission is what
# kills one of the seven fragment matches above:
#   "or", "ors"   would let 'no auth' reach "no author"
#   "ged", "ping" and any other doubled final consonant would let 'flag' reach
#                 "flagged". The three keywords that genuinely need a doubled
#                 consonant ("tag", "zip") are short and strict, and they spell
#                 their own doubling out in KEYWORD_ENDINGS below.
#   "ted"         would let 'formula' reach "formulated"
#   "able"        would let 'action' reach "actionable"
#   "ion", "ions" would let 'format' reach "formation". Every keyword that
#                 needs an "ion" form already IS that form in the word lists
#                 ("expression", "permission", "migration").
#
# Three fragment matches SURVIVE this list on purpose, because they are the
# same word inflected and the match is arguably correct:
#   'build'     on "building"    -> "ing"
#   'record'    on "recorded"    -> "ed"
#   'attribute' on "attributed"  -> "d"
# Refusing those means refusing "ing" and "ed" outright, which also loses
# "uploading" and "uploaded", and a false negative is the expensive direction
# here. See the queue note in role_matches.
#
# The "y" to "ies" plural is NOT here. It rewrites the stem rather than being
# appended to it, so it lives in last_word_pattern.
GENERAL_ENDINGS: tuple[str, ...] = (
    "s", "es",           # files, uploads, patches
    "ed", "d",           # uploaded, stored
    "ing", "ings",       # rendering, settings
    "er", "ers", "r", "rs",  # renderer, compiler, handlers
    "ly",                # internally, canonically, anonymously
)

# A run of digits may follow any loose keyword, and it may follow an ending too.
# This is a separate optional group rather than another entry above, because a
# numbered form is a version or an index and not an inflection: "jinja2" is the
# template engine's actual name, "html5" is the standard's name, and "input2",
# "command1" and "collections7" are how the corpus numbers its own examples.
# Measured over the corpus, this one rule alone saves about 1,700 word
# occurrences that bounding the tail would otherwise have dropped. It cannot
# bring back any of the seven fragment matches, because not one of them ends in
# a digit.
_TRAILING_DIGITS = r"(?:[0-9]+)?"

# Extra word endings, PER KEYWORD. For a STRICT keyword this is the only
# ending it may carry and the default is none at all. For a LOOSE keyword this
# is added ON TOP of GENERAL_ENDINGS, and it exists for the forms a general
# rule cannot reach: "configuration" is not "config" plus an English suffix,
# and "shellcode" is a compound, not an inflection.
#
# One shared list was tried across the STRICT keywords and it was wrong. It
# existed so that "exec" could reach "execute", but it was applied to every
# strict keyword, so the endings "s" and "d" turned the two letter acronym "ci"
# into "cis" and "cid". A SQL injection whose query parameter is named cid then
# reported two WORKFLOW_INSTRUCTION routes that nothing in the finding
# supported. That is why a strict keyword still gets nothing by default.
#
# So each keyword declares its own endings and the default is none at all.
# Every entry below was checked by writing out the words it produces and the
# words it must not produce.
KEYWORD_ENDINGS: dict[str, tuple[str, ...]] = {
    # execute, executed, executes, executing, execution, executions,
    # executable, executor, executors, execve, execs. NOT executive.
    "exec": ("utions", "utable", "utors", "uting", "ution", "utes", "utor", "uted", "ute", "ve", "s"),
    # evals only. "evaluation" and "evaluated" stay out on purpose: they are
    # ordinary English and they are not the eval() sink.
    "eval": ("s",),
    # imports, imported, importing, importer, importers. NOT important.
    "import": ("ers", "ing", "ed", "er", "s"),
    # The keyword "env var" must also reach "env variable" and "env vars".
    # Its last part is three letters so it is strict, and with no entry here
    # the phrase stopped matching "env variable" at all, which is a silent
    # loss of every route into CONFIGURATION.
    "var": ("iables", "iable", "s"),
    "arg": ("s",),   # args
    "acl": ("s",),   # acls
    "row": ("s",),   # rows
    "db": ("s",),    # dbs
    # Doubled final consonant. Both of these matched under the old substring
    # test and stopped matching when the edges went in, so they are a measured
    # regression and not a new feature. "tagged" and "tagging" are how a finding
    # says a record carries metadata, and "zipped" is how it says an archive.
    # The doubled letter is spelled out rather than derived, because deriving it
    # would also produce "roww" and "argg".
    "tag": ("ging", "ged", "s"),    # tags, tagged, tagging
    "zip": ("ping", "ped", "s"),    # zips, zipped, zipping
    # Plain plurals of three letter tokens. Each is strict at both edges, so the
    # only new token each one admits is exactly the plural spelled here. None of
    # these plurals is also an unrelated English word, which is the test that
    # "ci" failed: "cis" is the CIS benchmark and "cid" is an id parameter, so
    # "ci" still carries no endings at all.
    "job": ("s",),   # jobs
    "tar": ("s",),   # tars
    "mcp": ("s",),   # mcps
    "rce": ("s",),   # rces
    # Deliberately carrying no endings, so they match as the bare token only:
    #   ci, ini, raw, to, spel, reflect
    #
    # LOOSE keywords below this line. Each one is a form that GENERAL_ENDINGS
    # cannot reach and that the corpus diff measured as a real loss when the
    # tail was bounded. The occurrence counts are from
    # W-001-corpus-word-diff-output.txt, over every text file under security/.
    #
    # configuration, configurations, configured, configures, configuring,
    # configure, configurable. 2,326 occurrences, the largest single loss.
    "config": ("urations", "uration", "urable", "uring", "ures", "ured", "ure"),
    # filename, filenames, filesystem, filesystems, filesize, filesizes.
    # 1,209 occurrences. "fileno" and "filedescriptor" are left out: they are
    # C and Python identifiers, not the way a finding names a file.
    "file": ("systems", "system", "names", "name", "sizes", "size"),
    # administrator, administrators, administrative, administration.
    # 675 occurrences, and it feeds the P dimension, so losing it quietly
    # lowers the score of every finding that says "administrator" and never
    # says "admin".
    "admin": ("istrations", "istratively", "istrators", "istrative", "istrator", "istration"),
    # persistent, persistence, persistently, persistences. 541 occurrences,
    # and "persistent storage" is exactly what the STORED_DATA role is for.
    "persist": ("ently", "ences", "ence", "ents", "ent"),
    # formatter, formatting, formatted. 215 occurrences. Doubled final
    # consonant, spelled out for the same reason "tag" and "zip" spell theirs.
    "format": ("tings", "ters", "ting", "ted", "ter"),
    # compatibility, compatible, compatibles. 130 occurrences.
    "compat": ("ibilities", "ibility", "ibles", "ible"),
    # The last word of "no auth" and of "missing auth". This entry is the whole
    # reason those two keywords can still reach "no authentication" and
    # "missing authorization" while REFUSING "no author", which was one of the
    # ten fragment matches. The bad ending is "or" and it is not here; the two
    # real ones are, spelled out in full.
    "auth": (
        "entications", "entication", "enticated", "orizations", "orization",
        "orisations", "orisation", "orized", "orised", "entic",
    ),
}

# Boundaries are tested with [a-z0-9] rather than \b on purpose, see the note
# in role_matches. The text is lowercased before matching, so no [A-Z] class
# is needed here.
_LEFT_EDGE = r"(?<![a-z0-9])"
_RIGHT_EDGE = r"(?![a-z0-9])"
_SEPARATOR = r"[\s_\-]+"

# Camel case humps become spaces BEFORE the text is lowercased, so a keyword
# glued into an identifier still has an edge to sit against. "execFileSync"
# becomes "exec File Sync" and "URLClassLoader" becomes "URL Class Loader".
# Without this the left edge refused "loader" inside "URLClassLoader", so a
# real remote class loading route disappeared and nothing in the output said
# anything had been missed. The same split is what lets a multi word keyword
# reach its camel case form, so "query string" now reaches "queryString" and
# "env var" reaches "envVar".
# First rule: a lower case letter or a digit followed by a capital.
# Second rule: a capital followed by a capital and then a lower case letter,
# which is an acronym running into a word, as in the "URLC" of "URLClass".
_CAMEL_SPLITS = (
    re.compile(r"(?<=[a-z0-9])(?=[A-Z])"),
    re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])"),
)


def split_camel_case(text: str) -> str:
    """Put a space at every camel case hump, so edges exist inside identifiers."""
    for pattern in _CAMEL_SPLITS:
        text = pattern.sub(" ", text)
    return text


def match_forms(text: str) -> tuple[str, str]:
    """The two lowercased forms of the text that a keyword is tested against.

    Splitting camel case buys real matches and it also breaks real ones, because
    an acronym is not an identifier and the splitter cannot tell them apart.
    Measured, by calling split_camel_case directly:

        "arbitrary SpEL runs"  ->  "arbitrary sp el runs"
        "an APIcall is made"   ->  "an ap icall is made"

    "SpEL" is the standard capitalisation of the Spring Expression Language and
    it is how a real finding writes it. Cut in half it can never match the
    keyword "spel", so the EXPRESSION role vanished and an expression language
    injection lost its route. The same finding written "spel" in lower case
    scored 23 points higher, which means the score moved on capitalisation
    alone. That is a false negative the camel splitter INTRODUCED, and a false
    negative is the expensive direction here.

    So a keyword is tested against BOTH forms and matches if either one hits.
    The split form is what reaches "loader" inside "URLClassLoader". The plain
    form is what reaches "spel" inside "SpEL". Taking the union cannot add a
    fragment match that the plain form did not already allow, because the plain
    form is just the lowercased text with the same edge rules applied, which is
    what rounds 1 and 2 already matched against.
    """
    return split_camel_case(text).lower(), text.lower()


def keyword_endings(core: str, last: str, strict: bool) -> str:
    """The optional ending group for a keyword, empty when it has none.

    A strict keyword gets only what its own KEYWORD_ENDINGS entry allows, and
    most allow nothing. A loose keyword gets GENERAL_ENDINGS as well, which is
    what replaced the old open ended tail.
    """
    own = KEYWORD_ENDINGS.get(core) or KEYWORD_ENDINGS.get(last) or ()
    endings = tuple(own) if strict else tuple(dict.fromkeys(GENERAL_ENDINGS + tuple(own)))
    digits = "" if strict else _TRAILING_DIGITS
    if not endings:
        return digits
    # Longest first, because Python alternation takes the first branch that
    # matches and not the longest one.
    ordered = sorted(endings, key=len, reverse=True)
    return "(?:" + "|".join(re.escape(ending) for ending in ordered) + ")?" + digits


def last_word_pattern(last: str, strict: bool) -> str:
    """The regex for the final word of a keyword, where any ending is allowed.

    A loose keyword is matched as a prefix, and a prefix cannot reach a plural
    that rewrites the stem it grew from. "directory" does not begin the word
    "directories", so "the directories are listed" matched nothing at all, and
    the same silent miss hit "property", "policy", "recovery" and "retry". Those
    are ordinary words in a finding, so the loss was real and one sided: the
    matcher saw the singular and went blind on the plural.

    The plural branch spells out the exact letters "ies" and never "ie"
    followed by anything. That distinction is the whole safety of this rule.
    "retr" plus "ie" plus anything also swallows "retrieve", "retrieval" and
    "retrieved", and a RAG finding says "retrieval" in nearly every sentence,
    so the loose form would have put the deferred and fallback dimensions on
    every candidate the eduai work produces. Checked by running it: after this
    rule "retry" matches "retries" and still does not match "retrieval".
    """
    if strict or len(last) < MIN_LOOSE_LENGTH or not last.endswith("y"):
        return re.escape(last)
    return "(?:" + re.escape(last) + "|" + re.escape(last[:-1]) + "ies)"


def keyword_pattern(core: str) -> str:
    """Build the regex for one already lowercased, already stripped keyword."""
    parts = [part for part in re.split(_SEPARATOR, core) if part]
    if not parts:
        return ""
    left = _LEFT_EDGE if parts[0][0].isalnum() else ""
    last = parts[-1]
    strict = len(last) < MIN_LOOSE_LENGTH or last in STRICT_KEYWORDS or core in STRICT_KEYWORDS
    body = _SEPARATOR.join(
        [re.escape(part) for part in parts[:-1]] + [last_word_pattern(last, strict)]
    )
    if not last[-1].isalnum():
        right = ""
    else:
        # BOTH branches now end at a right edge. The loose branch used to end
        # at nothing at all, which is what let a loose keyword swallow any run
        # of trailing letters. The two branches differ only in which endings
        # they allow before that edge.
        right = keyword_endings(core, last, strict) + _RIGHT_EDGE
    return left + body + right


def role_matches(text: str, keywords: list[str]) -> list[str]:
    # Matching is word aware. It is NOT a plain substring test and it is NOT a
    # bare \b test either. Both of those were tried and both were wrong.
    #
    # The original bug: `keyword in lowered` fired "ci" inside "specified",
    # "acl" inside "oracle", "arg" inside "target" and "file" inside "profile".
    # Those are fragment matches and they invented transitions that were never
    # there.
    #
    # Round 1 replaced it with \b...\b, which traded one silent failure for two:
    #   * Python counts "_" as a word character, so \bpath\b can never match
    #     inside "file_path". Findings and code are full of snake_case names.
    #   * a boundary is not stemming, so "exec" stopped reaching "executed",
    #     "execution" and "execve", and a remote code execution finding then
    #     scored below a harmless logging note.
    #
    # What this version does:
    #   * edges are tested with [a-z0-9], so BOTH "_" and "-" act as
    #     separators. "file_path" now yields "file" and "path".
    #   * an internal space, underscore or hyphen in a keyword all match each
    #     other, so "query string" matches "query_string" and "query-string",
    #     and "auto-generated" matches "auto generated" and "auto_generated".
    #   * a keyword of MIN_LOOSE_LENGTH characters or more may be followed by a
    #     REAL WORD ENDING and then must stop at an edge, so "file" reaches
    #     "files", "upload" reaches "uploaded" and "directory" reaches
    #     "directories". The allowed endings are GENERAL_ENDINGS plus whatever
    #     that keyword's own KEYWORD_ENDINGS entry adds. Both edges are
    #     enforced. The left edge is what kills a fragment sitting in the middle
    #     or at the end of a word; the ending list is what kills a fragment at
    #     the start of one.
    #
    #     ROUND 5 CHANGED THIS AND THE PARAGRAPH BELOW IS THE HISTORY. Until
    #     round 5 a loose keyword could be followed by ANY run of letters, with
    #     no right edge at all. It was a prefix rule, so it fired on any longer
    #     word starting with the same letters, related or not. Ten were
    #     confirmed by running the matcher:
    #         'formula'   fired on "formulated"   -> EXPRESSION
    #         'flag'      fired on "flagged"      -> CONFIGURATION
    #         'tool'      fired on "toolbar"      -> TOOL_ARGUMENT
    #         'action'    fired on "actionable"   -> WORKFLOW_INSTRUCTION
    #         'html'      fired on "htmlspecialchars" -> TEMPLATE_DATA
    #         'path'      fired on "pathological" -> PATH_COMPONENT
    #         'no auth'   fired on "no author"    -> the C factor, 0.6 to 1.0
    #         'build'     fired on "building"     -> BUILD_INSTRUCTION
    #         'record'    fired on "recorded"     -> STORED_DATA
    #         'attribute' fired on "attributed"   -> METADATA
    #     Measured cost: an ordinary stored XSS finding whose text happens to
    #     say "the WAF flagged the request", "the admin toolbar" and "the reply
    #     the assistant formulated" earned three target roles it had no claim
    #     to, crossed them with two legitimate source roles, and reported SIX
    #     transitions that did not exist. It scored 59.1 where 44.1 is right.
    #     Evidence: red4-B1-fragment-transitions.json in the folder named below.
    #
    #     The old note here argued the defect could not be fixed without a
    #     stemmer and a dictionary, because "exec" must reach "executed" and
    #     "upload" must reach "uploaded". That argument was wrong, and naming
    #     why is the point of this paragraph. The bad tails are not word endings
    #     at all: "ological" ends nothing, "bar" ends nothing, while "ed" and
    #     "d" are ordinary English. So a SHORT BOUNDED LIST of real endings
    #     separates the two without any dictionary. Measured after the change,
    #     through scripts\mask0ff.cmd: the stored XSS case drops to 44.1 with
    #     zero transitions, and the seven fragment matches above the line are
    #     gone. The last three SURVIVE on purpose, because "building",
    #     "recorded" and "attributed" are the same words inflected and refusing
    #     them means refusing "ing" and "ed", which also loses "uploading" and
    #     "uploaded".
    #
    #     The direction the remaining errors point is still deliberate. This
    #     score sorts a work queue: a false positive costs one opened
    #     candidate, a false negative loses the finding. Where a rule could go
    #     either way it keeps the match. Evidence for round 5 is in
    #     W-001-defect-a-fix.txt, including the 332 corpus words that lost a
    #     match and why each group of them was accepted.
    #   * short keywords, and the abbreviations in STRICT_KEYWORDS, get both
    #     edges enforced and may carry only an ending their own KEYWORD_ENDINGS
    #     entry allows. Most of them allow none.
    #   * camel case humps are turned into spaces first, so a keyword glued
    #     into an identifier still has an edge. That is what makes "loader"
    #     match inside "URLClassLoader" and "exec" inside "execFileSync"
    #     without loosening the left edge for everything else.
    #   * a loose keyword ending in "y" also matches its "ies" plural, because
    #     a prefix rule alone never reaches "directories" from "directory".
    #     See last_word_pattern for why the branch is "ies" and not "ie".
    #
    # Which direction the remaining errors point, and why that is on purpose.
    # This matcher sorts a queue. A false positive costs the minute it takes to
    # open a boring candidate. A false negative sinks a real finding to the
    # bottom of a list of fifty, where nobody looks. So where a rule could go
    # either way it is written to keep the match, and the cost is paid in
    # candidates that turn out dull. The one exception is a pattern that would
    # fire on nearly EVERY candidate, because a signal that is always on is not
    # a signal at all and it stops ranking anything. That is the whole reason
    # "rce" is not allowed to fire inside "source" and "import" is not allowed
    # to fire inside "important".
    #
    # What this version still does NOT do, said plainly because the round 1
    # note overclaimed it: it does not remove whole word coincidence. "agent"
    # lifted from the User-Agent header still counts as TOOL_ARGUMENT, and
    # "json" in "the endpoint returns JSON" still counts as CONFIGURATION. No
    # edge rule can separate those from "path" inside "file_path", which must
    # keep matching: they are the same lexical shape and differ only in
    # meaning. Ranking that by meaning is a different mechanism, not a matcher
    # tweak. See evidence/phase2-3-2026-08-12/A-003-substring-fix-notes.txt.
    #
    # The live example of that limit, left in on purpose: "agent" sits in
    # TOOL_ARGUMENT and means an AI agent, but it also fires on the second half
    # of the "User-Agent" HTTP header, which is not a tool call at all. That is
    # a vocabulary problem, not a matcher problem, so it is NOT patched here.
    # The word list belongs to the engine's author and forking it locally would
    # split this copy from upstream. Measured cost, re measured 2026-08-12 after
    # the round 4 edit: red-in-4-useragent-coincidence keeps three invented
    # transitions into TOOL_ARGUMENT and scores 50.8. It is a note that says in
    # its own text that it is not a security issue. It stays below the real
    # command execution case, which scores 70.4, so the ranking survives the
    # false positive, but the three transitions are still wrong. Raise it with
    # the author. Numbers and commands in
    # evidence/phase2-3-2026-08-12/A-012-matcher-round4-build.txt.
    #
    # The second limit, also said plainly: a keyword glued into an ALL LOWER
    # CASE compound is still missed. "classloader", "safeloader" and
    # "importmap" carry no hump and no separator, so nothing marks where the
    # keyword starts. Catching those means allowing a keyword to begin in the
    # middle of a run of letters, which is the exact rule that put "file"
    # inside "profile" and started all of this. English compound splitting
    # needs a dictionary, not an edge rule, so this is left missing on purpose
    # rather than traded for the fragment matches back.
    forms = match_forms(text)
    matched = []
    for keyword in keywords:
        core = keyword.strip().lower()
        if not core:
            continue
        pattern = keyword_pattern(core)
        if pattern and any(re.search(pattern, form) for form in forms):
            matched.append(keyword)
    return matched


def detected_transitions(text: str) -> list[dict[str, str]]:
    hits: dict[str, list[str]] = {}
    for role, keywords in SEMANTIC_ROLES.items():
        matched = role_matches(text, keywords)
        if matched:
            hits[role] = matched
    transitions = []
    for source_role in ("RAW_DATA", "STORED_DATA", "METADATA", "PATH_COMPONENT", "FILESYSTEM_OBJECT"):
        if source_role not in hits:
            continue
        for target_role in (
            "TEMPLATE_DATA",
            "EXPRESSION",
            "CONFIGURATION",
            "GENERATED_CONFIGURATION",
            "COMMAND_ARGUMENT",
            "MODULE_IDENTIFIER",
            "WORKFLOW_INSTRUCTION",
            "TOOL_ARGUMENT",
            "BUILD_INSTRUCTION",
        ):
            if target_role in hits and target_role != source_role:
                transitions.append({"from": source_role, "to": target_role, "keywords": hits[target_role][:2]})
    return transitions


def factor(text: str, words: list[str]) -> float:
    # Routed through role_matches so that ONE matcher serves every dimension.
    # Before this, factor() did a plain `word in lowered` substring test while
    # role_matches did not, so the two disagreed on the same text. Measured
    # consequences of the plain test, all from A-004-red-substring-fix.txt:
    #   "the source of the value" -> I=1.0, because "source" contains "rce"
    #   "more information is logged" -> G=1.0, because it contains "format"
    #   "this is important" -> A=1.0, because it contains "import"
    #   "an evaluation of the answer" -> I=1.0, because it contains "eval"
    # Those four carry 0.25 of the 1.00 weight budget between them.
    return 1.0 if role_matches(text, words) else 0.0


# The literal word tests that used to sit inline in weird_surface_score. They
# are lifted out unchanged, only so they can go through factor() like every
# other dimension. No word was added, removed or reworded.
ATTACKER_WORDS = ["attacker"]
CROSSING_WORDS = ["store", "persist", "save", "write", "insert"]


def weird_surface_score(text: str) -> tuple[float, dict[str, float]]:
    scores = {
        "C": 1.0 if factor(text, AUTH_BOUNDARY_WORDS) or factor(text, ATTACKER_WORDS) else 0.6,
        "M": 1.0 if detected_transitions(text) else 0.0,
        "X": 0.7 if factor(text, CROSSING_WORDS) else 0.0,
        "P": factor(text, PRIVILEGE_WORDS),
        "G": factor(text, GRAMMAR_WORDS),
        "D": factor(text, DEFERRED_WORDS),
        "I": factor(text, INTERPRETER_WORDS),
        "A": factor(text, LOW_ATTENTION_WORDS),
        "F": factor(text, FALLBACK_WORDS),
        "N": 0.5,
    }
    weighted = sum(WSS_WEIGHTS[key] * scores[key] for key in WSS_WEIGHTS)
    return round(100 * weighted, 1), scores


def novelty(candidate: dict[str, Any], cases_path: Path) -> tuple[float, str]:
    cases = json.loads(cases_path.read_text(encoding="utf-8-sig"))["cases"]
    candidate_text = " ".join(
        str(candidate.get(field, "")) for field in ("component", "entry_point", "source_sink", "primitive", "impact")
    ).lower()
    candidate_tokens = {t for t in tokens(candidate_text) if t not in NOVELTY_EXEMPT}
    if not candidate_tokens:
        return 0.0, "no-comparable-corpus"
    best = 0.0
    best_id = ""
    for case in cases:
        case_text = " ".join(
            str(case.get(field, "")) for field in ("title", "summary", "component", "primitive", "impact")
        )
        overlap = len(candidate_tokens & tokens(case_text)) / len(candidate_tokens | tokens(case_text))
        if overlap > best:
            best = overlap
            best_id = str(case.get("id", ""))
    return round(1.0 - best, 3), best_id


def evidence_confidence(record: dict[str, Any] | None) -> dict[str, Any]:
    if not record:
        return {"confidence": 0.0, "basis": "no-finding-record"}
    gates = record.get("gates", {}) if isinstance(record.get("gates"), dict) else {}
    passed = [gate for gate in EVIDENCE_GATES if isinstance(gates.get(gate), dict) and gates[gate].get("status") == "pass"]
    missing = [gate for gate in EVIDENCE_GATES if gate not in passed]
    fraction = len(passed) / len(EVIDENCE_GATES)
    return {
        "confidence": round(fraction, 3),
        "basis": "finding-record-gates",
        "passed": passed,
        "missing": missing,
    }


# Field values are joined with this, and never with a plain space.
#
# A plain space put the last word of one field next to the first word of the
# next, so a multi word keyword could be assembled from a phrase no human
# wrote. Measured: "parameter" ended source_sink, "to" started primitive, and
# an email header injection with no command, shell or process in it reported
# RAW_DATA->COMMAND_ARGUMENT and METADATA->COMMAND_ARGUMENT on the keyword
# "parameter to". All 14 multi word keywords were exposed the same way.
#
# The pipe is chosen because _SEPARATOR is [\s_\-]+ and does not include it,
# so no multi word keyword can span the join. It is not alphanumeric either,
# so it still counts as an edge and a single word keyword at the start or the
# end of a field keeps matching.
_FIELD_JOIN = " | "


def scored_text(value: Any) -> str:
    """Flatten a candidate into the text the matcher reads: VALUES only.

    run() used to score json.dumps(candidate), which put the FIELD NAMES into
    the text as well. The field names are the schema, not anything a human
    reported, so every candidate earned roles for free: "source_sink" gave
    METADATA nothing but gave INTERPRETER_WORDS its "rce", "entry_point" gave
    PATH_COMPONENT its "path", a key called "title" gave METADATA a hit. The
    quotes, braces and commas json.dumps adds are dropped too, so nothing
    joins two neighbouring values into one accidental word.
    """
    if isinstance(value, dict):
        return _FIELD_JOIN.join(scored_text(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return _FIELD_JOIN.join(scored_text(item) for item in value)
    if value is None:
        return ""
    return str(value)


def run(candidate: dict[str, Any], record: dict[str, Any] | None, cases_path: Path) -> dict[str, Any]:
    text = scored_text(candidate)
    transitions = detected_transitions(text)
    wss, factors = weird_surface_score(text)
    novelty_value, nearest = novelty(candidate, cases_path)
    ec = evidence_confidence(record)
    factors["N"] = novelty_value
    weighted = sum(WSS_WEIGHTS[key] * factors[key] for key in WSS_WEIGHTS)
    wss = round(100 * weighted, 1)
    final_priority = round(wss * ec["confidence"], 1)
    return {
        "schema_version": 1,
        "weird_surface_score": wss,
        "evidence_confidence": ec,
        "final_priority": final_priority,
        "factors": {key: round(value, 3) for key, value in factors.items()},
        "semantic_transitions": transitions,
        "novelty": {"value": novelty_value, "nearest_case": nearest},
        "interpretation": {
            "wss": "search priority, not severity",
            "priority": "final_priority ranks candidates; evidence outranks model confidence",
            "high_value_route": bool(transitions and factors["I"]),
        },
        "route_summary": (
            "Unexpected route to an old primitive: "
            + " -> ".join(f"{t['from']}->{t['to']}" for t in transitions[:3])
            if transitions
            else "no explicit semantic transition detected"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Score a candidate by ZDE-style weird-surface and evidence priority.")
    parser.add_argument("--candidate", type=Path, help="JSON object with fingerprint fields (component, entry_point, source_sink, primitive, impact, boundary)")
    parser.add_argument("--finding", type=Path, help="Finding-record JSON to derive evidence confidence")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        candidate: dict[str, Any] = {}
        record: dict[str, Any] | None = None
        if args.candidate:
            value = json.loads(args.candidate.read_text(encoding="utf-8-sig"))
            if not isinstance(value, dict):
                raise ValueError("candidate JSON must be an object")
            candidate_value = value.get("fingerprint", value)
            if not isinstance(candidate_value, dict):
                raise ValueError("candidate fingerprint must be an object")
            candidate = candidate_value
        if args.finding:
            value = json.loads(args.finding.read_text(encoding="utf-8-sig"))
            if not isinstance(value, dict):
                raise ValueError("finding record must be an object")
            record = value
            candidate_value = value.get("fingerprint", {})
            if not isinstance(candidate_value, dict):
                raise ValueError("finding fingerprint must be an object")
            candidate = candidate_value
        if not candidate:
            parser.error("a --candidate or --finding with a non-empty fingerprint is required")
        result = run(candidate, record, args.cases)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
