"""Offline synthetic checks, not a SIEM backend or original incident replay."""
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path
import json
import re
import yaml
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parent
TEXT = (ROOT / 'sigma.yml').read_text(encoding='utf-8')
COLLECTION = SigmaCollection.from_yaml(TEXT)
BASE, CORRELATION = list(yaml.safe_load_all(TEXT))
CORR = CORRELATION['correlation']
assert BASE['name'] in CORR['rules']
assert CORR['type'] == 'event_count'
assert BASE['detection']['condition'] == 'selection'
assert CORR['condition'] == {'gte': 4}
assert CORR['timespan'] == '60s'
assert CORR['group-by'] == ['host', 'src_ip', 'username']
assert 'attack.t1110' in BASE['tags'] and 'attack.t1110' in CORRELATION['tags']


def event(seconds, **overrides):
    value = dict(timestamp=(datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)).isoformat(),
                 host='synthetic-target', src_ip='192.0.2.10', username='synthetic-user',
                 message='Failed password for synthetic-user from 192.0.2.10 port 12345 ssh2')
    value.update(overrides)
    return value


def matches(events):
    """Evaluate specified lab logic with a half-open sliding window (t-60, t].

    Select the actual YAML message predicate and grouping fields. This small
    reference evaluator is not a general Sigma interpreter or backend converter.
    Missing grouping fields are an ingestion error, not an empty-field group.
    """
    needle = BASE['detection']['selection']['message|contains']
    queues = defaultdict(deque)
    seconds = int(CORR['timespan'][:-1])
    threshold = CORR['condition']['gte']
    found = False
    for value in sorted(events, key=lambda v: datetime.fromisoformat(v['timestamp'])):
        if needle not in value.get('message', ''):
            continue
        if any(not value.get(field) for field in CORR['group-by']):
            raise ValueError('Missing normalized grouping field')
        key = tuple(value[field] for field in CORR['group-by'])
        moment = datetime.fromisoformat(value['timestamp'])
        queue = queues[key]
        while queue and (moment - queue[0]).total_seconds() >= seconds:
            queue.popleft()
        queue.append(moment)
        found |= len(queue) >= threshold
    return found


cases = [
    ('reported_four_failure_pattern_synthetic', [event(n) for n in [0, 3, 5, 7]] + [event(8, message='Accepted password')], True),
    ('three_failures_below_threshold', [event(n) for n in [0, 3, 5]], False),
    ('four_failures_outside_window', [event(n) for n in [0, 30, 60, 90]], False),
    ('separate_sources_do_not_combine', [event(n, src_ip='192.0.2.' + str(10 + n)) for n in range(4)], False),
    ('separate_accounts_do_not_combine', [event(n, username='user' + str(n)) for n in range(4)], False),
    ('separate_hosts_do_not_combine', [event(n, host='host' + str(n)) for n in range(4)], False),
    ('successful_logins_not_counted', [event(n, message='Accepted password') for n in range(4)], False),
    ('unrelated_messages_not_counted', [event(n, message='system service started') for n in range(4)], False),
    ('inside_window_boundary', [event(n) for n in [0, 1, 2, 59]], True),
    ('exact_window_boundary_excluded', [event(n) for n in [0, 1, 2, 60]], False),
    ('unordered_input_is_sorted', [event(n) for n in [7, 0, 5, 3]], True),
    ('benign_four_typos_can_alert', [event(n, username='legitimate-test-user') for n in range(4)], True),
]
results = []
for name, fixture, expected in cases:
    actual = matches(fixture)
    assert actual == expected, (name, actual, expected)
    results.append(dict(case=name, expected=expected, observed=actual, passed=True))
try:
    matches([event(0, username=None)])
except ValueError:
    results.append(dict(case='missing_grouping_field_rejected', passed=True))
else:
    raise AssertionError('Missing grouping field was accepted')

for name in ['README.md', 'incident_report.md']:
    for link in re.findall(r'\]\(([^)]+)\)', (ROOT / name).read_text(encoding='utf-8')):
        if not link.startswith(('https://', 'http://', '#')):
            assert (ROOT / link).is_file(), (name, 'broken link', link)

versions = {name: version(name) for name in ['pysigma', 'PyYAML']}
report = dict(scope='Synthetic fixtures and parser validation only; no live SIEM execution.',
              window='half-open sliding (t-60s, t]; deployment backend semantics must be checked',
              dependencies=versions, sigma_parser_passed=True, local_links_passed=True, cases=results)
(ROOT / 'validation-results.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
(ROOT / 'requirements-validation.txt').write_text('\n'.join(name + '==' + value for name, value in versions.items()) + '\n', encoding='utf-8')
print('PASS: Sigma collection parsed, local links valid,', len(results), 'synthetic cases passed.')
print('Not tested: live SIEM conversion, ingestion mappings, deployed alerts or original raw-log replay.')
