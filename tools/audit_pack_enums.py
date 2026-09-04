#!/usr/bin/env python3
"""Check every pack's activity_id mapping against the vendored OCSF schema.

A pack maps a vendor's own vocabulary onto OCSF enum values by hand, and
nothing in the fixture suite catches a number that is simply wrong: the pack
compiles, the fixture asserts whatever the pack produces, and the event is
schema-shaped. It is only wrong in meaning.

That is not hypothetical. Two packs numbered HTTP methods in the order someone
wrote them down rather than the order OCSF defines, so every GET was recorded
as Connect and every POST as Delete. Both passed their fixtures.

    python tools/audit_pack_enums.py

Exits non-zero if any pack maps a name to an activity id whose caption in
schema/ocsf is a different name.
"""
import json, glob, os, re, sys

cats = json.load(open('schema/ocsf/categories.json', encoding='utf-8'))['attributes']
byname = {k: v['uid'] for k, v in cats.items()}
folder_to_cat = {
    'system': 'system', 'findings': 'findings', 'iam': 'iam', 'network': 'network',
    'discovery': 'discovery', 'application': 'application', 'remediation': 'remediation',
    'unmanned_systems': 'unmanned_systems',
}

# class_uid -> {caption, activities {id: caption}}
classes = {}
for f in glob.glob('schema/ocsf/events/**/*.json', recursive=True):
    d = json.load(open(f, encoding='utf-8'))
    uid = d.get('uid')
    if uid is None:
        continue
    cat = d.get('category')
    if cat not in byname:
        cat = folder_to_cat.get(os.path.basename(os.path.dirname(f)))
    if cat not in byname:
        continue
    acts = d.get('attributes', {}).get('activity_id', {}).get('enum', {})
    classes[byname[cat] * 1000 + uid] = {
        'caption': d.get('caption'),
        'acts': {int(k): v['caption'] for k, v in acts.items()},
    }

SEVERITY = {0: 'Unknown', 1: 'Informational', 2: 'Low', 3: 'Medium',
            4: 'High', 5: 'Critical', 6: 'Fatal', 99: 'Other'}

problems = 0
for path in sorted(glob.glob('packs/*.yaml')):
    text = open(path, encoding='utf-8').read()
    m = re.search(r'class_uid:\s*(\d+)', text)
    if not m:
        continue
    cls = int(m.group(1))
    info = classes.get(cls)
    name = os.path.basename(path)
    if not info:
        print(f"{name}: class_uid {cls} is not in the vendored schema")
        problems += 1
        continue

    # which enum table feeds activity_id?
    am = re.search(r'activity_id:\s*\n\s*from:.*?\n\s*enum:\s*(\S+)', text)
    if not am:
        continue
    table = am.group(1)
    tm = re.search(r'^\s{2}' + re.escape(table) + r':\s*\n((?:\s{4}.*\n)+)', text, re.M)
    if not tm:
        continue

    valid = info['acts']
    for line in tm.group(1).splitlines():
        em = re.match(r'\s+"?([^":]+)"?:\s*(\d+)', line)
        if not em:
            continue
        key, val = em.group(1).strip(), int(em.group(2))
        if val == 99:
            continue
        caption = valid.get(val)
        # a method name should map to the activity whose caption matches it
        expected = next((i for i, c in valid.items()
                         if c.replace(' ', '').replace('-', '').upper() == key.replace('_', '').upper()), None)
        if expected is not None and expected != val:
            print(f"{name}: {table}.{key} = {val} ({caption}) but OCSF says {key} is {expected}")
            problems += 1
        elif caption is None:
            print(f"{name}: {table}.{key} = {val} is not a valid activity_id for "
                  f"class {cls} ({info['caption']})")
            problems += 1

print()
print(f"{problems} problem(s) found across {len(glob.glob('packs/*.yaml'))} packs")
sys.exit(1 if problems else 0)
