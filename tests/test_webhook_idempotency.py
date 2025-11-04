from indico_payment_niubiz.utils import WebhookIdempotencyCache


def test_idempotency_cache_blocks_duplicates():
    cache = WebhookIdempotencyCache(ttl_seconds=10)
    first = cache.mark_if_new("evt-1", now=100.0)
    second = cache.mark_if_new("evt-1", now=105.0)
    assert first is True
    assert second is False


def test_idempotency_cache_expires_entries():
    cache = WebhookIdempotencyCache(ttl_seconds=5)
    assert cache.mark_if_new("evt-2", now=10.0)
    cache.purge_expired(now=14.0)
    assert not cache.mark_if_new("evt-2", now=14.5)
    cache.purge_expired(now=16.0)
    assert cache.mark_if_new("evt-2", now=16.0)
