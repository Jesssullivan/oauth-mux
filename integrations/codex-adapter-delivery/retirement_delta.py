"""Bounded, fail-closed source transformation; never writes a source tree."""

MAX_SOURCE_BYTES = 4 * 1024 * 1024


def transform(source: bytes) -> bytes:
    if not isinstance(source, bytes) or len(source) > MAX_SOURCE_BYTES:
        raise ValueError("source byte bound exceeded")
    text = source.decode("utf-8")
    start = "    pub async fn shutdown_all_threads_bounded("
    if text.count(start) != 1:
        raise ValueError("shutdown method boundary mismatch")
    prefix, body = text.split(start, 1)
    end = body.find("\n    pub ")
    # A later private method or closing impl is also a valid boundary. Only
    # exact, unique snippets below are rewritten; unrelated bytes are retained.
    boundaries = [body.find(marker) for marker in ("\n    pub ", "\n    async fn ", "\n    fn ", "\n}")]
    end = min(index for index in boundaries if index >= 0)
    method, suffix = body[:end], body[end:]
    replacements = (
        ("                (thread_id, outcome)", "                (thread_id, thread, outcome)"),
        ("        let mut report = ThreadShutdownReport::default();", "        let mut report = ThreadShutdownReport::default();\n        let mut completed_runtimes = Vec::new();"),
        ("        while let Some((thread_id, outcome)) = shutdowns.next().await {", "        while let Some((thread_id, thread, outcome)) = shutdowns.next().await {"),
        ("                ShutdownOutcome::Complete => report.completed.push(thread_id),", "                ShutdownOutcome::Complete => {\n                    report.completed.push(thread_id);\n                    completed_runtimes.push((thread_id, thread));\n                }"),
        ("        for thread_id in &report.completed {\n            tracked_threads.remove(thread_id);\n        }", "        for (thread_id, completed_runtime) in &completed_runtimes {\n            if tracked_threads\n                .get(thread_id)\n                .is_some_and(|current| Arc::ptr_eq(current, completed_runtime))\n            {\n                tracked_threads.remove(thread_id);\n            }\n        }"),
    )
    for before, after in replacements:
        if method.count(before) != 1:
            raise ValueError("retirement source predicate mismatch")
        method = method.replace(before, after, 1)
    return (prefix + start + method + suffix).encode("utf-8")
