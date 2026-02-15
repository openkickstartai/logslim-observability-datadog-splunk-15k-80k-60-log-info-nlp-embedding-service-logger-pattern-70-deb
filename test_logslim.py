"""Tests for LogSlim core engine."""
import json
import pytest
from logslim import analyze, normalize, parse_line

SAMPLE_LOGS = [
    '{"service":"api","level":"DEBUG","message":"Processing request for user abc"}',
    '{"service":"api","level":"DEBUG","message":"Processing request for user xyz"}',
    '{"service":"api","level":"DEBUG","message":"Processing request for user qrs"}',
    '{"service":"worker","level":"INFO","message":"Health check OK"}',
    '{"service":"worker","level":"INFO","message":"Health check OK"}',
    '{"service":"worker","level":"INFO","message":"Health check OK"}',
    '{"service":"worker","level":"INFO","message":"Health check OK"}',
    '{"service":"worker","level":"INFO","message":"Health check OK"}',
    '{"service":"auth","level":"ERROR","message":"Login failed from 192.168.1.100"}',
    '{"service":"auth","level":"ERROR","message":"Login failed from 10.0.0.55"}',
]


def test_normalize_replaces_variable_tokens():
    assert '<UUID>' in normalize('req abc12345-abcd-1234-abcd-abcdef123456 done')
    assert '<IP>' in normalize('Connection from 192.168.1.1 refused')
    assert '<NUM>' in normalize('Processed 42 items in 100ms')
    assert '<HEX>' in normalize('pointer at 0xDEADBEEF')
    result = normalize('2024-01-15T10:30:00Z user 99')
    assert '<TS>' in result
    assert '<NUM>' in result


def test_parse_line_json_structured():
    parsed = parse_line('{"service":"api","level":"INFO","message":"hello world"}')
    assert parsed is not None
    assert parsed['service'] == 'api'
    assert parsed['level'] == 'INFO'
    assert parsed['msg'] == 'hello world'
    assert 'service' in parsed['fields']


def test_parse_line_plaintext_fallback():
    parsed = parse_line('2024-01-01 ERROR something broke badly')
    assert parsed is not None
    assert parsed['level'] == 'ERROR'
    assert 'something broke' in parsed['msg']
    assert parsed['service'] == 'unknown'


def test_parse_line_empty():
    assert parse_line('') is None
    assert parse_line('   ') is None


def test_parse_line_warning_normalized():
    parsed = parse_line('{"level":"WARNING","message":"disk full"}')
    assert parsed['level'] == 'WARN'


def test_analyze_groups_similar_patterns():
    result = analyze(SAMPLE_LOGS)
    assert result['pattern_count'] >= 3
    assert result['total_bytes'] > 0
    assert result['total_cost'] >= 0
    health = [p for p in result['patterns'] if 'Health' in p['pattern']]
    assert len(health) == 1
    assert health[0]['count'] == 5
    login = [p for p in result['patterns'] if 'Login' in p['pattern']]
    assert len(login) == 1
    assert login[0]['count'] == 2
    assert '<IP>' in login[0]['pattern']


def test_analyze_cost_attribution_per_service():
    result = analyze(SAMPLE_LOGS)
    all_services = set()
    for p in result['patterns']:
        all_services.update(p['services'])
    assert 'api' in all_services
    assert 'worker' in all_services
    assert 'auth' in all_services


def test_analyze_detects_noise_in_health_checks():
    result = analyze(SAMPLE_LOGS)
    health = [p for p in result['patterns'] if 'Health' in p['pattern']]
    assert health[0]['noise_score'] > 0


def test_analyze_generates_recommendations_for_noisy_logs():
    debug_logs = [f'{{"service":"svc","level":"DEBUG","message":"Verbose debug output {i}"}}'
                  for i in range(50)]
    health_logs = ['{"service":"mon","level":"INFO","message":"Health check OK"}'] * 100
    result = analyze(debug_logs + health_logs)
    assert len(result['recommendations']) > 0
    actions = [r['action'] for r in result['recommendations']]
    assert any(a in ('DROP_OR_SAMPLE', 'RAISE_LOG_LEVEL') for a in actions)
    for r in result['recommendations']:
        assert r['est_savings_pct'] > 0


def test_analyze_empty_input():
    result = analyze([])
    assert result['pattern_count'] == 0
    assert result['total_cost'] == 0
    assert result['total_bytes'] == 0
    assert result['recommendations'] == []
    assert result['patterns'] == []


def test_analyze_custom_rate():
    result_default = analyze(SAMPLE_LOGS, rate_per_gb=0.10)
    result_splunk = analyze(SAMPLE_LOGS, rate_per_gb=0.60)
    assert result_splunk['total_cost'] == pytest.approx(result_default['total_cost'] * 6, rel=1e-6)


def test_analyze_json_output_serializable():
    result = analyze(SAMPLE_LOGS)
    serialized = json.dumps(result, default=str)
    parsed_back = json.loads(serialized)
    assert parsed_back['pattern_count'] == result['pattern_count']
