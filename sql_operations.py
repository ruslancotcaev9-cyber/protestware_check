"""Bounded SQL lexical masking and statement-level PostgreSQL TRUNCATE detection."""
from bisect import bisect_right
import re

DOLLAR = re.compile(r'\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$')
WORD = re.compile(r'[A-Za-z_\u0080-\uffff][\w$]*')


def lex(text):
    index, count, size = 0, 0, len(text)
    while index < size:
        start = index
        char = text[index]
        if char.isspace():
            index += 1
            continue
        kind = 'punctuation'
        if text.startswith('--', index):
            end = text.find('\n', index)
            index = size if end < 0 else end
            kind = 'comment'
        elif text.startswith('/*', index):
            index += 2
            depth = 1
            while index < size and depth:
                if text.startswith('/*', index):
                    depth += 1
                    index += 2
                elif text.startswith('*/', index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            kind = 'comment'
        elif char in "'\"`":
            quote = char
            # PostgreSQL E'...' permits escaped quotes; ordinary strings do not.
            escaped = quote == "'" and index > 0 and text[index - 1] in 'eE' and (index < 2 or not (text[index - 2].isalnum() or text[index - 2] in '_$'))
            index += 1
            while index < size:
                if escaped and text[index] == '\\':
                    index += 2
                elif text[index] == quote:
                    index += 1
                    if index < size and text[index] == quote:
                        index += 1
                    else:
                        break
                else:
                    index += 1
            index = min(index, size)
            kind = 'literal' if quote == "'" else 'identifier'
        elif char == '$' and (match := DOLLAR.match(text, index)):
            delimiter = match.group()
            end = text.find(delimiter, match.end())
            index = size if end < 0 else end + len(delimiter)
            kind = 'literal'
        elif match := WORD.match(text, index):
            index = match.end()
            kind = 'word'
        else:
            index += 1
        count += 1
        if count > 200000:
            raise ValueError('SQL lexical token budget exceeded')
        yield kind, text[start:index], start, index


def mask(text):
    result = list(text)
    for kind, value, start, end in lex(text):
        if kind not in {'comment', 'literal', 'identifier'}:
            continue
        quoted = kind == 'identifier' or (kind == 'literal' and value.startswith("'"))
        for index in range(start, end):
            if result[index] != '\n' and not (quoted and index in {start, end - 1}):
                result[index] = '_' if kind == 'identifier' else ' '
    return ''.join(result)


def truncates(text):
    """Recognize command starts, never function calls, strings or identifiers."""
    tokens = [token for token in lex(text) if token[0] != 'comment']
    newlines = [index for index, char in enumerate(text) if char == '\n']
    results, start = [], True
    for index, (kind, value, offset, _) in enumerate(tokens):
        if start and kind == 'word' and value.upper() == 'TRUNCATE':
            cursor = index + 1
            for optional in ('TABLE', 'ONLY'):
                if cursor < len(tokens) and tokens[cursor][0] == 'word' and tokens[cursor][1].upper() == optional:
                    cursor += 1
            if cursor < len(tokens) and tokens[cursor][0] in {'word', 'identifier'}:
                results.append(bisect_right(newlines, offset) + 1)
        start = kind == 'punctuation' and value == ';'
    return results
