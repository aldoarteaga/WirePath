#!/usr/bin/env python3
"""Checks string catalogs: every live key has a Spanish translation, plural variations cover `one` and `other`,
and translations keep the same format specifiers as their key. Exits non-zero on problems."""
import json, re, sys

SPEC = re.compile(r'%(?:\d+\$)?(?:lld|ld|d|@|f|\.\d+f|%)|%#@\w+@')

def specifiers(text):
    return sorted(s for s in re.findall(r'%(?:\d+\$)?(lld|ld|d|@|\.?\d*f)', text))

def units(entry):
    """All (label, value) strings of one localization."""
    if 'stringUnit' in entry:
        yield 'value', entry['stringUnit']['value']
    for kind, forms in entry.get('variations', {}).items():
        for form, unit in forms.items():
            yield f'{kind}.{form}', unit['stringUnit']['value']

problems = 0
for path in sys.argv[1:]:
    catalog = json.load(open(path))
    live = {k: v for k, v in catalog['strings'].items() if v.get('extractionState') != 'stale' and v.get('shouldTranslate', True)}
    for key, value in live.items():
        es = value.get('localizations', {}).get('es')
        if not es:
            print(f'{path}: missing Spanish: {key!r}')
            problems += 1
            continue
        plural = es.get('variations', {}).get('plural')
        if plural and not {'one', 'other'} <= plural.keys():
            print(f'{path}: plural without one/other: {key!r}')
            problems += 1
        # Specifiers must match the key, except inside substitutions (checked by their argNum).
        if 'substitutions' not in es:
            for label, text in units(es):
                if specifiers(text) != specifiers(key) and not (plural and specifiers(text) == [] ):
                    print(f'{path}: specifiers differ in {label}: {key!r} → {text!r}')
                    problems += 1
    stale = [k for k, v in catalog['strings'].items() if v.get('extractionState') == 'stale']
    print(f'{path}: {len(live)} strings, {len(stale)} stale')
sys.exit(1 if problems else 0)
