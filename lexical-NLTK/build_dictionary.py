from pathlib import Path
import re

import nltk
from nltk.stem import WordNetLemmatizer


BASE_DIR = Path(__file__).resolve().parent

ADVISORY_DIR = BASE_DIR / "domain dict texts" / "eng" / "github advisory database"
OUTPUT_FILE = BASE_DIR / "ib_dictionary.txt"


def ensure_wordnet():
    try:
        nltk.data.find("corpora/wordnet")
    except LookupError:
        print("WordNet not found. Downloading...")
        nltk.download("wordnet")


def extract_words(text):
    # Только обычные английские слова.
    # Технические сущности classifier уже должен был убрать.
    return re.findall(r"[A-Za-z]+(?:['-][A-Za-z]+)*", text)


def lemmatize_word(lemmatizer, word):
    word = word.lower()

    # Для начала используем noun + verb.
    # Это позволяет, например:
    # vulnerabilities -> vulnerability
    # attacks -> attack
    # exploited -> exploit
    lemma = lemmatizer.lemmatize(word, pos="n")
    lemma = lemmatizer.lemmatize(lemma, pos="v")

    return lemma


def main():
    ensure_wordnet()

    lemmatizer = WordNetLemmatizer()
    dictionary = set()

    files = sorted(ADVISORY_DIR.glob("advisory_*.txt"))

    print(f"Found {len(files)} advisory files")

    for path in files:
        print(f"Processing: {path.name}")

        text = path.read_text(
            encoding="utf-8",
            errors="ignore",
        )

        words = extract_words(text)

        for word in words:
            lemma = lemmatize_word(lemmatizer, word)

            if lemma:
                dictionary.add(lemma)

    OUTPUT_FILE.write_text(
        "\n".join(sorted(dictionary)) + "\n",
        encoding="utf-8",
    )

    print()
    print(f"Dictionary entries: {len(dictionary)}")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()