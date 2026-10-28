from auth_capture_explainer.latency import Summary, percentile


def test_nearest_rank():
    values = list(range(1, 11))
    assert [percentile(values, q) for q in (1, 50, 90, 95, 99, 100)] == [1, 5, 9, 10, 10, 10]


def test_summary():
    s = Summary.of([0.3, 0.1, 0.2])
    assert (s.count, s.p50, s.p95, s.p99, s.max) == (3, 0.2, 0.3, 0.3, 0.3)


def test_single_and_empty():
    assert Summary.of([0.5]) == Summary(1, 0.5, 0.5, 0.5, 0.5)
    assert Summary.of([]) == Summary(0)
    assert Summary.of(x for x in ()) == Summary(0)
