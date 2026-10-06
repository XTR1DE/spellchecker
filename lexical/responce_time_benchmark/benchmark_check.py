from pathlib import Path
import json
import time
import urllib.request


BASE_DIR = Path(__file__).resolve().parent
TEXT_PATH = BASE_DIR / "words.txt"

CLASSIFIER_URL = "http://127.0.0.1:8090/tokenize"
TOKENS_URL = "http://127.0.0.1:8090/tokens"
LEXICAL_URL = "http://127.0.0.1:8091/check"


def post_json(url, payload):
    data = json.dumps(
        payload,
        ensure_ascii=False,
    ).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )

    with urllib.request.urlopen(request) as response:
        return json.loads(
            response.read().decode("utf-8")
        )


def get_json(url):
    request = urllib.request.Request(
        url,
        method="GET",
    )

    with urllib.request.urlopen(request) as response:
        return json.loads(
            response.read().decode("utf-8")
        )


def classify(text):
    # Запускаем токенизацию.
    post_json(
        CLASSIFIER_URL,
        {"text": text},
    )

    # Забираем реально сохраненные токены.
    return get_json(TOKENS_URL)


def send_batch(batch, started):
    data = json.dumps(
        {"words": batch},
        ensure_ascii=False,
    ).encode("utf-8")

    request = urllib.request.Request(
        LEXICAL_URL,
        data=data,
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )

    results = []
    first_result = None
    last_result = None

    with urllib.request.urlopen(request) as response:
        for line in response:
            if not line.strip():
                continue

            result = json.loads(line)

            elapsed = time.perf_counter() - started

            if first_result is None:
                first_result = elapsed

            last_result = elapsed
            results.append(result)

    return results, first_result, last_result


def run_batch(words, batch_size):
    started = time.perf_counter()

    results = []
    first_result = None
    last_result = None
    requests = 0

    for pos in range(0, len(words), batch_size):
        batch = words[pos:pos + batch_size]
        requests += 1

        batch_results, first, last = send_batch(
            batch,
            started,
        )

        if first_result is None:
            first_result = first

        last_result = last
        results.extend(batch_results)

    total = time.perf_counter() - started

    return (
        total,
        first_result,
        last_result,
        requests,
        results,
    )


def check_order(words, results):
    if len(words) != len(results):
        return False

    expected = [
        (
            word["start"],
            word["end"],
            word["text"],
        )
        for word in words
    ]

    actual = [
        (
            result.get("start"),
            result.get("end"),
            result.get("text"),
        )
        for result in results
    ]

    return expected == actual


def main():
    text = TEXT_PATH.read_text(
        encoding="utf-8"
    )

    print(f"Text: {TEXT_PATH}")
    print(f"Text size: {len(text)} chars")
    print()

    # --------------------------------------------------
    # CLASSIFIER
    # --------------------------------------------------

    print("Calling classifier...")

    classifier_started = time.perf_counter()

    tokens = classify(text)

    classifier_time = (
        time.perf_counter()
        - classifier_started
    )

    # Берем только реальные WORD-токены,
    # которые вернул classifier.
    words = [
        {
            "start": token["start"],
            "end": token["end"],
            "text": token["text"],
        }
        for token in tokens
        if token.get("type") == "WORD"
    ]

    print(
        f"Classifier time: "
        f"{classifier_time * 1000:.2f} ms"
    )

    print(f"Total tokens: {len(tokens)}")
    print(f"WORD tokens: {len(words)}")
    print()

    # --------------------------------------------------
    # LEXICAL BENCHMARK
    # --------------------------------------------------

    cases = [
        ("batch all", len(words)),
        ("batch 200", 200),
        ("batch 100", 100),
        ("batch 50", 50),
    ]

    results = []

    for name, batch_size in cases:
        print(f"Running: {name} ...")

        (
            total,
            first,
            last,
            requests,
            lexical_results,
        ) = run_batch(
            words,
            batch_size,
        )

        results.append({
            "name": name,
            "total": total,
            "first": first,
            "last": last,
            "requests": requests,
            "received": len(lexical_results),
            "order": check_order(
                words,
                lexical_results,
            ),
        })

    # --------------------------------------------------
    # RESULTS
    # --------------------------------------------------

    print()
    print("=" * 105)

    print(
        f"{'Strategy':<18}"
        f"{'Total ms':>12}"
        f"{'First ms':>12}"
        f"{'Last ms':>12}"
        f"{'HTTP':>8}"
        f"{'Recv':>8}"
        f"{'Order':>8}"
    )

    print("=" * 105)

    for result in results:
        print(
            f"{result['name']:<18}"
            f"{result['total'] * 1000:>12.2f}"
            f"{result['first'] * 1000:>12.2f}"
            f"{result['last'] * 1000:>12.2f}"
            f"{result['requests']:>8}"
            f"{result['received']:>8}"
            f"{'OK' if result['order'] else 'FAIL':>8}"
        )

    print("=" * 105)


if __name__ == "__main__":
    main()