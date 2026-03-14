from core.detector.stored import StoredXSSTracker


def test_stored_tracker():

    tracker = StoredXSSTracker()

    injection = {
        "url": "http://example.com/comment",
        "parameter": "msg",
        "payload": '<script>alert("VSW_TEST")</script>'
    }

    tracker.track(injection)

    assert len(tracker.tracked_payloads) == 1