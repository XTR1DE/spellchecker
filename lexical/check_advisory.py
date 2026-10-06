
from pathlib import Path
import json

from flask import Flask, request, Response, stream_with_context
from nltk.stem import WordNetLemmatizer


BASE_DIR = Path(__file__).resolve().parent
DICTIONARY_FILE = BASE_DIR / "ib_dictionary.txt"

app = Flask(__name__)

lemmatizer = WordNetLemmatizer()


def load_dictionary():
    if not DICTIONARY_FILE.exists():
        raise RuntimeError(
            f"IB dictionary not found: {DICTIONARY_FILE}"
        )

    return {
        line.strip().lower()
        for line in DICTIONARY_FILE.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    }


IB_DICTIONARY = load_dictionary()


def lemmatize_word(word):
    word = word.lower()

    lemma = lemmatizer.lemmatize(word, pos="n")
    lemma = lemmatizer.lemmatize(lemma, pos="v")

    return lemma


def process_words(words):
    """
    Обрабатывает WORD последовательно и сразу
    отдаёт каждый результат как отдельную NDJSON-строку.
    """

    for word in words:
        start = word.get("start")
        end = word.get("end")
        text = word.get("text")

        try:
            if not isinstance(text, str) or not text:
                raise ValueError("text must be a non-empty string")

            lemma = lemmatize_word(text)

            # Если слово уже находится в начальной форме,
            # оно не считается IB даже если lemma есть в словаре.
            is_ib = (
                text != lemma
                and lemma in IB_DICTIONARY
            )

            result = {
                "start": start,
                "end": end,
                "text": text,
                "lemma": lemma,
                "ib": is_ib,
            }

        except Exception as exc:
            # Ошибка одного WORD не роняет весь stream.
            result = {
                "start": start,
                "end": end,
                "text": text,
                "error": str(exc),
            }

        yield json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
        ) + "\n"


@app.post("/check")
def check():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return {
            "status": "error",
            "message": "JSON object expected",
        }, 400

    words = data.get("words")

    if not isinstance(words, list):
        return {
            "status": "error",
            "message": "words must be an array",
        }, 400

    return Response(
        stream_with_context(process_words(words)),
        content_type="application/x-ndjson",
    )


@app.get("/health")
def health():
    return {
        "status": "ok",
        "dictionary_size": len(IB_DICTIONARY),
    }


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=8091,
        debug=False,
        threaded=False,
    )
