"""LogSlim — Core log cost attribution and noise detection engine."""
import re
import json
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field as dfield

NORMALIZERS = [
    (re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I), '<UUID>'),
    (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '<IP>'),
    (re.compile(r'\b\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}[.\d]*Z?\b'), '<TS>'),
    (re.compile(r'\b0x[0-9a-f]+\b', re.I), '<HEX>'),
    (re.compile(r'\b\d+\b'), '<NUM>'),
]
LEVEL_RE = re.compile(r'\b(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|TRACE)\b', re.I)
DEFAULT_RATE = 0.10  # $/GB — Datadog-like ingestion pricing
NOISE_KEYWORDS = ['health', 'heartbeat', 'ping', 'alive', 'ready', 'liveness', 'keepalive']


@dataclass
class PatternGroup:
    pattern: str
    fingerprint: str
    count: int = 0
    total_bytes: int = 0
    services: set = dfield(default_factory=set)
    levels: dict = dfield(default_factory=lambda: defaultdict(int))
    sample: str = ""
    field_keys: set = dfield(default_factory=set)


def normalize(msg: str) -> str:
    """Replace variable tokens (UUIDs, IPs, numbers, etc.) with placeholders."""
    for rx, repl in NORMALIZERS:
        msg = rx.sub(repl, msg)
    return msg


def parse_line(raw: str):
    """Parse a single log line — supports JSON and plaintext."""
    raw = raw.strip()
    if not raw:
        return None
    try:
        obj = json.loads(raw)
        msg = obj.get('msg') or obj.get('message') or obj.get('log') or str(obj)
        svc = obj.get('service') or obj.get('app') or obj.get('source') or 'unknown'
        lvl = (obj.get('level') or obj.get('severity') or '').upper()
        if lvl == 'WARNING':
            lvl = 'WARN'
        return {'msg': msg, 'service': svc, 'level': lvl, 'fields': set(obj.keys()), 'raw': raw}
    except (json.JSONDecodeError, AttributeError):
        m = LEVEL_RE.search(raw)
        lvl = m.group(1).upper() if m else 'UNKNOWN'
        if lvl == 'WARNING':
            lvl = 'WARN'
        return {'msg': raw, 'service': 'unknown', 'level': lvl, 'fields': set(), 'raw': raw}


def analyze(lines, rate_per_gb=DEFAULT_RATE):
    """Analyze log lines → pattern groups, cost attribution, noise scores, recommendations."""
    groups = {}
    for raw in lines:
        p = parse_line(raw)
        if not p:
            continue
        norm = normalize(p['msg'])
        fp = hashlib.md5(norm.encode()).hexdigest()[:12]
        if fp not in groups:
            groups[fp] = PatternGroup(pattern=norm, fingerprint=fp, sample=p['raw'][:200])
        g = groups[fp]
        g.count += 1
        g.total_bytes += len(p['raw'].encode('utf-8'))
        g.services.add(p['service'])
        if p['level']:
            g.levels[p['level']] += 1
        g.field_keys |= p['fields']
    total_bytes = sum(g.total_bytes for g in groups.values())
    total_cost = (total_bytes / 1e9) * rate_per_gb
    results = []
    for g in sorted(groups.values(), key=lambda x: x.total_bytes, reverse=True):
        cost = (g.total_bytes / 1e9) * rate_per_gb
        pct = (g.total_bytes / total_bytes * 100) if total_bytes > 0 else 0
        results.append({
            'fingerprint': g.fingerprint, 'pattern': g.pattern[:120],
            'count': g.count, 'bytes': g.total_bytes, 'cost': cost, 'pct': pct,
            'services': sorted(g.services), 'levels': dict(g.levels),
            'noise_score': _noise_score(g, pct), 'sample': g.sample,
            'field_count': len(g.field_keys),
        })
    return {'total_bytes': total_bytes, 'total_cost': total_cost, 'patterns': results,
            'recommendations': _recommend(results), 'pattern_count': len(results)}


def _noise_score(g, pct):
    """Score 0-100: higher = more likely noise / safe to drop."""
    score = 0.0
    dbg_frac = (g.levels.get('DEBUG', 0) + g.levels.get('TRACE', 0)) / max(g.count, 1)
    score += dbg_frac * 40
    if pct > 10:
        score += min(pct, 30)
    if any(kw in g.pattern.lower() for kw in NOISE_KEYWORDS):
        score += 20
    return min(round(score, 1), 100)


def _recommend(patterns):
    """Generate actionable cost-reduction recommendations."""
    recs = []
    for p in patterns:
        if p['noise_score'] >= 50:
            recs.append({'action': 'DROP_OR_SAMPLE', 'fingerprint': p['fingerprint'],
                         'reason': f"Noise score {p['noise_score']}, {p['pct']:.1f}% of volume",
                         'est_savings_pct': round(p['pct'] * 0.9, 1), 'pattern': p['pattern'][:80]})
        elif p['levels'].get('DEBUG', 0) > p['count'] * 0.5:
            recs.append({'action': 'RAISE_LOG_LEVEL', 'fingerprint': p['fingerprint'],
                         'reason': '>50% DEBUG logs — raise to INFO in production',
                         'est_savings_pct': round(p['pct'] * 0.8, 1), 'pattern': p['pattern'][:80]})
        elif p['field_count'] > 20:
            recs.append({'action': 'TRIM_FIELDS', 'fingerprint': p['fingerprint'],
                         'reason': f"{p['field_count']} fields — trim unused to cut payload size",
                         'est_savings_pct': round(p['pct'] * 0.3, 1), 'pattern': p['pattern'][:80]})
    return recs


def analyze_with_store(lines, rate_per_gb=DEFAULT_RATE, db_path=None, source_file=None):
    """Analyze logs — uses DuckDB for large datasets (>=50MB) or when db_path is set, in-memory otherwise."""
    sample_size = min(len(lines), 1000)
    if sample_size == 0:
        return analyze(lines, rate_per_gb=rate_per_gb)

    sample_bytes = sum(len(l.encode('utf-8', errors='replace')) for l in lines[:sample_size])
    estimated_total = (sample_bytes / sample_size) * len(lines)

    if estimated_total < 50 * 1024 * 1024 and db_path is None:
        return analyze(lines, rate_per_gb=rate_per_gb)

    from storage import LogStore
    store = LogStore(db_path=db_path)
    store.clear()

    records = []
    for raw in lines:
        parsed = parse_line(raw)
        if parsed is None:
            continue
        pattern = normalize(parsed['msg'])
        fp = hashlib.md5(pattern.encode()).hexdigest()
        records.append({
            'fingerprint': fp,
            'service': parsed['service'],
            'level': parsed['level'],
            'raw_size_bytes': parsed['raw_bytes'],
            'pattern': pattern,
            'timestamp': None,
            'source_file': source_file or '',
        })

    store.ingest(records)
    top = store.top_patterns(limit=1000)
    service_costs = store.cost_by_service(price_per_gb=rate_per_gb)
    total_bytes = store.con.execute("SELECT COALESCE(SUM(raw_size_bytes), 0) FROM logs").fetchone()[0]

    patterns_out = []
    for p in top:
        pct = p['pct_of_total']
        noise_score = 0
        if pct > 10:
            noise_score += 40
        elif pct > 5:
            noise_score += 25
        elif pct > 1:
            noise_score += 10
        pat_lower = p['pattern'].lower()
        if any(kw in pat_lower for kw in NOISE_KEYWORDS):
            noise_score += 20
        patterns_out.append({
            'fingerprint': hashlib.md5(p['pattern'].encode()).hexdigest(),
            'pattern': p['pattern'],
            'count': p['count'],
            'total_bytes': p['total_bytes'],
            'pct_of_total': p['pct_of_total'],
            'services': p['services'],
            'noise_score': round(min(noise_score, 100), 1),
            'cost_usd': round(p['total_bytes'] / 1e9 * rate_per_gb, 4),
        })

    store.close()

    return {
        'patterns': patterns_out,
        'pattern_count': len(patterns_out),
        'total_bytes': total_bytes,
        'total_cost_usd': round(total_bytes / 1e9 * rate_per_gb, 4),
        'rate_per_gb': rate_per_gb,
        'service_costs': service_costs,
    }
