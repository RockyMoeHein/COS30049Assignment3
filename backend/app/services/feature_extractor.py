"""
Compact C/C++ security feature extractor for CVEfixes C CWE classification.

Target CWE set:
- CWE-119  : Improper Restriction of Operations within the Bounds of a Memory Buffer
- CWE-120  : Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
- CWE-469  : Use of Pointer Subtraction to Determine Size
- CWE-476  : NULL Pointer Dereference
- CWE-OTHERS : Other / generalized CWE patterns (integer issues, resource mgmt, format strings, etc.)

Design:
- Compact semantic risk levels
- General C/C++ memory/input/null-safety counters
"""

import re
from typing import Dict


# ─── Utility ────────────────────────────────────────────────────────────────

def _strip_comments(code: str) -> str:
    code = re.sub(r'//[^\n]*', '', str(code))
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    return code


def _strip_strings(code: str) -> str:
    code = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', str(code))
    code = re.sub(r"'[^'\\]*(?:\\.[^'\\]*)*'", "''", code)
    return code


def _clean(code: str) -> str:
    return _strip_strings(_strip_comments(str(code))).lower()


def _contains_any(text: str, keywords: list[str]) -> int:
    return int(any(k in text for k in keywords))


def _count_any(text: str, keywords: list[str]) -> int:
    return sum(text.count(k) for k in keywords)


def _regex_count(pattern: str, code: str) -> int:
    return len(re.findall(pattern, str(code)))


# ─── Keyword Groups ─────────────────────────────────────────────────────────

# CWE-119 / CWE-120: Buffer operations (unsafe = classic overflow candidates)
UNSAFE_BUFFER_FUNCS = [
    'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets',
    'scanf', 'sscanf', 'memcpy', 'memmove', 'wcscpy', 'wcscat'
]

BOUNDED_BUFFER_FUNCS = [
    'strncpy', 'strncat', 'snprintf', 'vsnprintf', 'fgets',
    'memset_s', 'strlcpy', 'strlcat', 'wcsncpy', 'wcsncat'
]

# CWE-469: Pointer subtraction used to determine size/length
POINTER_SUBTRACTION_PATTERNS = [
    r'[a-zA-Z_][A-Za-z0-9_]*\s*-\s*[a-zA-Z_][A-Za-z0-9_]*',   # ptr_a - ptr_b
    r'\bptrdiff_t\b',
    r'\bptrdiff\b',
]

# CWE-476: NULL pointer dereference
NULL_RELATED_FUNCS = [
    'malloc', 'calloc', 'realloc', 'fopen', 'fgets', 'strdup',
    'new ', 'getenv', 'popen', 'opendir', 'dlopen'
]

NULL_CHECK_KW = [
    'null', 'nullptr', '!= null', '== null', 'if', 'assert'
]

# CWE-OTHERS: Generalized signals (integer overflow, format string,
#             resource leak, use-after-free, double free, etc.)
FORMAT_STRING_FUNCS = [
    'printf', 'fprintf', 'syslog', 'vprintf', 'vfprintf'
]

RESOURCE_FUNCS = [
    'fopen', 'popen', 'opendir', 'socket', 'malloc', 'calloc',
    'realloc', 'new '
]

RESOURCE_RELEASE_FUNCS = [
    'fclose', 'pclose', 'closedir', 'close', 'free', 'delete'
]

INTEGER_OVERFLOW_FUNCS = [
    'atoi', 'atol', 'atoll', 'strtol', 'strtoul', 'strtoll',
    'strtoull', 'sscanf'
]

MEMORY_ALLOCATION_FUNCS = [
    'malloc', 'calloc', 'realloc', 'alloca', 'new '
]

MEMORY_RELEASE_FUNCS = [
    'free', 'delete'
]

INPUT_FUNCS = [
    'scanf', 'fscanf', 'sscanf', 'gets', 'fgets', 'read', 'recv',
    'recvfrom', 'getenv', 'argv', 'stdin', 'getchar', 'getc'
]

VALIDATION_KW = [
    'if', 'assert', 'sizeof', 'strlen', 'strncmp', 'strcmp',
    '<', '>', '<=', '>=', '!=', '==', 'return', 'exit', 'abort'
]

BOUND_CHECK_KW = [
    'sizeof', 'strlen', 'strnlen', 'capacity', 'len', 'length',
    'size', 'bounds', 'limit', '<', '>', '<=', '>='
]

POINTER_DEREF_PATTERNS = [
    r'\*\s*[a-zA-Z_][A-Za-z0-9_]*',
    r'[a-zA-Z_][A-Za-z0-9_]*\s*->\s*[a-zA-Z_]'
]

INTEGER_TYPES = [
    'int', 'short', 'long', 'unsigned', 'signed',
    'size_t', 'ssize_t', 'uint', 'uint32_t', 'uint64_t',
    'int32_t', 'int64_t'
]


# ─── Semantic Risk-Level Features ───────────────────────────────────────────

def buffer_memory_risk_level(code: str) -> int:
    """
    CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer.
    General memory-buffer risk based on unsafe operations and missing bounds signals.

    0 = no strong buffer pattern
    1 = buffer/array/memory operations with some bounded/sizing signal
    2 = unsafe buffer/memory operation without clear bounds signal
    """
    c = _clean(code)

    has_unsafe = _contains_any(c, UNSAFE_BUFFER_FUNCS)
    has_bounded = _contains_any(c, BOUNDED_BUFFER_FUNCS)
    has_array = bool(re.search(r'\[[^\]]+\]', c))
    has_bounds = _contains_any(c, BOUND_CHECK_KW)

    if has_unsafe and not has_bounds:
        return 2
    if has_unsafe or has_array or has_bounded:
        return 1
    return 0


def classic_overflow_risk_level(code: str) -> int:
    """
    CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow').
    Specifically targets copy/input functions used without size-checking the source.

    0 = no classic overflow pattern
    1 = unsafe copy/input function present with some size/bound check signal
    2 = unsafe copy/input function present without any size/bound check signal
    """
    c = _clean(code)

    # Core CWE-120 functions: copy/read without explicit size limit
    CLASSIC_OVERFLOW_FUNCS = [
        'strcpy', 'strcat', 'gets', 'scanf', 'sscanf',
        'sprintf', 'vsprintf', 'wcscpy', 'wcscat'
    ]

    has_classic = _contains_any(c, CLASSIC_OVERFLOW_FUNCS)
    has_size_check = _contains_any(c, BOUND_CHECK_KW)

    if has_classic and not has_size_check:
        return 2
    if has_classic:
        return 1
    return 0


def pointer_subtraction_risk_level(code: str) -> int:
    """
    CWE-469: Use of Pointer Subtraction to Determine Size.
    Detects pointer arithmetic subtraction used as a size/length proxy.

    0 = no pointer subtraction pattern
    1 = pointer subtraction present alongside bounds/size awareness
    2 = pointer subtraction used without clear bounds/size validation
    """
    c = _clean(code)

    has_ptr_sub = any(re.search(p, c) for p in POINTER_SUBTRACTION_PATTERNS)
    has_pointer = bool(re.search(r'(\*\s*[a-zA-Z_]|->)', c))
    has_bounds = _contains_any(c, BOUND_CHECK_KW)

    if has_ptr_sub and not has_bounds:
        return 2
    if has_ptr_sub or (has_pointer and has_bounds):
        return 1
    return 0


def null_pointer_risk_level(code: str) -> int:
    """
    CWE-476: NULL Pointer Dereference.
    Detects nullable pointer sources dereferenced without NULL checks.

    0 = no nullable pointer pattern
    1 = nullable pointer/API with NULL-check signal
    2 = pointer/API dereference without clear NULL-check signal
    """
    c = _clean(code)

    has_nullable_api = _contains_any(c, NULL_RELATED_FUNCS)
    has_deref = any(re.search(p, c) for p in POINTER_DEREF_PATTERNS)
    has_null_check = _contains_any(c, NULL_CHECK_KW)

    if (has_nullable_api or has_deref) and not has_null_check:
        return 2
    if has_nullable_api or has_deref:
        return 1
    return 0


def other_cwe_risk_level(code: str) -> int:
    """
    CWE-OTHERS: Generalized risk signal for other common CWE patterns not
    covered by CWE-119/120/469/476. Covers:
      - Format string vulnerabilities (CWE-134)
      - Integer overflow/truncation (CWE-190, CWE-197)
      - Resource leak / improper release (CWE-401, CWE-772)
      - Double-free / use-after-free proximity signal (CWE-415, CWE-416)

    0 = no generalized risk signal
    1 = one generalized risk category present
    2 = multiple generalized risk categories present
    """
    c = _clean(code)

    signals = 0

    # Format string: printf-family called with non-literal/variable format arg
    if _contains_any(c, FORMAT_STRING_FUNCS):
        # Heuristic: format string risk if no string literal pattern nearby
        if not re.search(r'"%[^"]*"', c):
            signals += 1

    # Integer overflow / unsafe numeric conversion
    if _contains_any(c, INTEGER_OVERFLOW_FUNCS):
        if not _contains_any(c, VALIDATION_KW):
            signals += 1

    # Resource leak: resource opened but no matching release
    has_resource = _contains_any(c, RESOURCE_FUNCS)
    has_release = _contains_any(c, RESOURCE_RELEASE_FUNCS)
    if has_resource and not has_release:
        signals += 1

    # Double-free / use-after-free: free/delete appears more than once on
    # same type of resource, or free follows pointer arithmetic
    release_count = _count_any(c, MEMORY_RELEASE_FUNCS)
    alloc_count = _count_any(c, MEMORY_ALLOCATION_FUNCS)
    if release_count > 0 and release_count > alloc_count:
        signals += 1

    if signals >= 2:
        return 2
    if signals == 1:
        return 1
    return 0


def integer_size_risk_level(code: str) -> int:
    """
    Supporting signal for memory bounds bugs (integer misuse near allocations).

    0 = no integer/size pattern
    1 = integer arithmetic/cast exists
    2 = integer arithmetic used near allocation/array/memory operations
    """
    c = _clean(code)

    has_int_type = _contains_any(c, INTEGER_TYPES)
    arithmetic_count = _regex_count(r'[\+\-\*/%]', c)
    has_cast = bool(re.search(r'\([a-z_][a-z0-9_\s\*]*\)', c))
    has_size_context = _contains_any(c, ['sizeof', 'malloc', 'calloc', 'realloc', '[', 'memcpy'])

    if has_int_type and arithmetic_count > 0 and has_size_context:
        return 2
    if has_int_type and (arithmetic_count > 0 or has_cast):
        return 1
    return 0


# ─── Count / Intensity Features ─────────────────────────────────────────────

def count_unsafe_buffer_funcs(code: str) -> int:
    """Count of unsafe buffer function calls (CWE-119/120 signal)."""
    return _count_any(_clean(code), UNSAFE_BUFFER_FUNCS)


def count_bounded_buffer_funcs(code: str) -> int:
    """Count of size-bounded buffer function calls (mitigation signal)."""
    return _count_any(_clean(code), BOUNDED_BUFFER_FUNCS)


def count_pointer_subtractions(code: str) -> int:
    """Count of pointer subtraction expressions (CWE-469 signal)."""
    c = _clean(code)
    return sum(_regex_count(p, c) for p in POINTER_SUBTRACTION_PATTERNS)


def count_memory_allocs(code: str) -> int:
    """Count of dynamic memory allocation calls."""
    return _count_any(_clean(code), MEMORY_ALLOCATION_FUNCS)


def count_memory_releases(code: str) -> int:
    """Count of memory release calls (free/delete)."""
    return _count_any(_clean(code), MEMORY_RELEASE_FUNCS)


def count_input_sources(code: str) -> int:
    """Count of external/user-controlled input function calls."""
    return _count_any(_clean(code), INPUT_FUNCS)


def count_validation_signals(code: str) -> int:
    """Count of validation/guard keyword occurrences."""
    return _count_any(_clean(code), VALIDATION_KW)


def count_array_accesses(code: str) -> int:
    """Count of array index expressions."""
    return _regex_count(r'\[[^\]]+\]', code)


def count_pointer_ops(code: str) -> int:
    """Count of pointer-related operators (*, ->, &)."""
    c = str(code)
    return c.count('*') + c.count('->') + c.count('&')


def count_null_checks(code: str) -> int:
    """Count of NULL-check related keyword occurrences (CWE-476 mitigation signal)."""
    return _count_any(_clean(code), NULL_CHECK_KW)


def count_format_string_funcs(code: str) -> int:
    """Count of printf-family function calls (CWE-OTHERS: format string signal)."""
    return _count_any(_clean(code), FORMAT_STRING_FUNCS)


def count_arithmetic_ops(code: str) -> int:
    """Count of arithmetic operators."""
    return _regex_count(r'[\+\-\*/%]', _clean(code))


def count_integer_types(code: str) -> int:
    """Count of integer type keyword occurrences."""
    return _count_any(_clean(code), INTEGER_TYPES)


# ─── Structural Features ────────────────────────────────────────────────────

def snippet_length(code: str) -> int:
    return sum(1 for line in str(code).splitlines() if line.strip())


def token_count(code: str) -> int:
    return len(re.findall(
        r'[A-Za-z_][A-Za-z0-9_]*|\d+|==|!=|<=|>=|->|\+\+|--|\S',
        str(code)
    ))


def max_brace_depth(code: str) -> int:
    depth = 0
    max_depth = 0

    for ch in str(code):
        if ch == '{':
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch == '}':
            depth = max(depth - 1, 0)

    return max_depth


def char_diversity(code: str) -> float:
    code = str(code)
    if len(code) == 0:
        return 0.0
    return len(set(code)) / len(code)


# ─── Main Feature Extractor ─────────────────────────────────────────────────

def extract_features(code: str) -> Dict[str, float]:
    """
    Compact C/C++ feature set for CVEfixes target CWEs:
    CWE-119, CWE-120, CWE-469, CWE-476, CWE-OTHERS.
    """
    return {
        # ── Semantic risk levels (one per target CWE) ──────────────────────
        # CWE-119: Improper Restriction of Operations within Bounds of Memory Buffer
        'buffer_memory_risk_level':       buffer_memory_risk_level(code),
        # CWE-120: Buffer Copy without Checking Size of Input
        'classic_overflow_risk_level':    classic_overflow_risk_level(code),
        # CWE-469: Use of Pointer Subtraction to Determine Size
        'pointer_subtraction_risk_level': pointer_subtraction_risk_level(code),
        # CWE-476: NULL Pointer Dereference
        'null_pointer_risk_level':        null_pointer_risk_level(code),
        # CWE-OTHERS: Generalized (format string, int overflow, resource leak, UAF/DF)
        'other_cwe_risk_level':           other_cwe_risk_level(code),

        # Supporting integer/size risk (common root cause across CWE-119/120)
        'integer_size_risk_level':        integer_size_risk_level(code),

        # ── Count / intensity features ─────────────────────────────────────
        'count_unsafe_buffer_funcs':      count_unsafe_buffer_funcs(code),
        'count_bounded_buffer_funcs':     count_bounded_buffer_funcs(code),
        'count_pointer_subtractions':     count_pointer_subtractions(code),
        'count_memory_allocs':            count_memory_allocs(code),
        'count_memory_releases':          count_memory_releases(code),
        'count_input_sources':            count_input_sources(code),
        'count_validation_signals':       count_validation_signals(code),
        'count_array_accesses':           count_array_accesses(code),
        'count_pointer_ops':              count_pointer_ops(code),
        'count_null_checks':              count_null_checks(code),
        'count_format_string_funcs':      count_format_string_funcs(code),
        'count_arithmetic_ops':           count_arithmetic_ops(code),
        'count_integer_types':            count_integer_types(code),

        # ── Structural features ────────────────────────────────────────────
        'snippet_length':                 snippet_length(code),
        'token_count':                    token_count(code),
        'max_brace_depth':                max_brace_depth(code),
        'char_diversity':                 char_diversity(code),
    }