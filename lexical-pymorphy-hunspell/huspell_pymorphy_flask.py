"""Spellchecker для ИБ-текстов: Hunspell + pymorphy3 + словарь ИБ-терминов.

Порядок проверки слова (как только слово признано верным - дальше не идём):
  1. слово есть в ib_dictionary.txt            -> пропуск
  2. слово уже проверялось (кэш)
  3. pymorphy3 знает слово (обычная лексика)   -> пропуск
  4. лемма слова есть в ИБ-словаре             -> пропуск
  5. Hunspell считает слово верным             -> пропуск
  6. ищем исправление: сначала в ИБ-словаре, потом среди подсказок Hunspell
  7. исправления нет -> слово становится кандидатом (candidates.json).
     После PROMOTE_THRESHOLD встреч кандидат переезжает в ib_dictionary.txt
     и удаляется из candidates.json.

Латиницу (powershell, mimikatz...) pymorphy3 и русский Hunspell не знают,
поэтому для неё шаги 3-5 пропускаются.
"""

import json
import logging
import os
import re
import subprocess
import time
import threading
from pathlib import Path

import pymorphy3
from flask import Flask, Response, jsonify, request, stream_with_context

try:
    from nltk.stem import WordNetLemmatizer
except ImportError:
    WordNetLemmatizer = None


logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")
log = logging.getLogger("spellchecker")

BASE_DIR = Path(__file__).resolve().parent

HUNSPELL_EXE = BASE_DIR / "Hunspell" / "bin" / "hunspell.exe"
HUNSPELL_DIC = BASE_DIR / "hunspell-1.7.3" / "ru_RU.dic"

# Должна совпадать со строкой SET в ru_RU.aff (koi8-r или utf-8)
HUNSPELL_ENCODING = "koi8-r"

IB_DICTIONARY = BASE_DIR / "data" / "ib_dictionary.txt"
CANDIDATES_FILE = BASE_DIR / "data" / "candidates.json"

# Сколько раз кандидат должен встретиться, чтобы попасть в ИБ-словарь
PROMOTE_THRESHOLD = 15

# Короткие слова (ИБ, ssh, smb, rdp...) не исправляем: слишком много совпадений
MIN_FIX_LEN = 4

# True  - исправляем только если правка "похожа на опечатку" (перестановка букв,
#         удвоение буквы, путаница а/о, е/и, и/ы, a/e, i/y...) - и для подсказок
#         Hunspell, и для поиска по ИБ-словарю.
#         Жаргон ("кредов", "логов") не превращается в случайные слова.
# False - исправляем любую правку на расстоянии 1.
STRICT_EDITS = True

# Стартовый ИБ-словарь: записывается в ib_dictionary.txt при первом запуске
# (если файла нет или он пуст). Эти слова всегда считаются верными.
SEED_TERMS = []

VALID, CORRECT, CANDIDATE = "valid", "correct", "candidate"


PROTECTED = re.compile(
    r"https?://\S+"
    r"|www\.\S+"
    r"|(?:\d{1,3}\.){3}\d{1,3}"
    r"|CVE-\d{4}-\d{4,7}"
    r"|(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])"
    r"|(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])"
    r"|(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])"
    r"|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}",
    re.IGNORECASE
)

# Дефис и апостроф - разделители: "powershell-скрипт" даст два токена
WORD = re.compile(r"[A-Za-zА-Яа-яЁё0-9]+")

LATIN_ONLY = re.compile(r"[A-Za-z]+")
CYRILLIC_ONLY = re.compile(r"[А-Яа-яЁё]+")

LATIN_ALPHABET = "abcdefghijklmnopqrstuvwxyz"
CYRILLIC_ALPHABET = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"

# Частицы после дефиса ("кто-нибудь"), которые pymorphy3 отдельно не знает.
# Пропускаются ТОЛЬКО если стоят сразу после дефиса.
HYPHEN_PARTICLES = {"то", "либо", "нибудь", "таки", "ка", "де", "кась", "тка"}


# ----------------------------------------------------------------------
# Вспомогательные функции
# ----------------------------------------------------------------------

def edits1(word):
    """Все слова на расстоянии одной правки:
    удаление, перестановка соседних букв, замена, вставка."""
    alphabet = LATIN_ALPHABET if LATIN_ONLY.fullmatch(word) else CYRILLIC_ALPHABET
    splits = [(word[:i], word[i:]) for i in range(len(word) + 1)]

    deletes = {a + b[1:] for a, b in splits if b}
    swaps = {a + b[1] + b[0] + b[2:] for a, b in splits if len(b) > 1}
    replaces = {a + c + b[1:] for a, b in splits if b for c in alphabet}
    inserts = {a + c + b for a, b in splits for c in alphabet}

    return (deletes | swaps | replaces | inserts) - {word}


# Пары букв, которые часто путают при письме
CONFUSED_PAIRS = {
    frozenset(p)
    for p in ("ао", "еи", "иы",                  # кириллица
              "ae", "ei", "iy", "sz", "vw", "ck")  # латиница
}


def is_typo_edit(wrong, right):
    """Правка wrong -> right (на расстоянии 1) похожа на опечатку?"""
    la, lb = len(wrong), len(right)

    # Одинаковая длина: замена или перестановка
    if la == lb:
        diffs = [i for i in range(la) if wrong[i] != right[i]]

        if len(diffs) == 1:
            return frozenset((wrong[diffs[0]], right[diffs[0]])) in CONFUSED_PAIRS

        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            i, j = diffs
            return wrong[i] == right[j] and wrong[j] == right[i]

        return False

    # Разница в одну букву: она должна дублировать соседнюю ("процес" -> "процесс")
    if abs(la - lb) != 1:
        return False

    longer, shorter = (wrong, right) if la > lb else (right, wrong)

    for j in range(len(longer)):
        if longer[:j] + longer[j + 1:] != shorter:
            continue

        if j > 0 and longer[j] == longer[j - 1]:
            return True

        if j + 1 < len(longer) and longer[j] == longer[j + 1]:
            return True

    return False


def match_case(src, repl):
    """Подгоняет регистр исправления под исходное слово."""
    if len(src) > 1 and src.isupper():
        return repl.upper()
    if src[:1].isupper():
        return repl[:1].upper() + repl[1:]
    return repl


def write_text_atomic(path, text):
    """Пишем во временный файл и переименовываем - файл не останется битым."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


# ----------------------------------------------------------------------
# Спеллчекер
# ----------------------------------------------------------------------

class SpellChecker:

    def __init__(self):
        start = time.perf_counter()

        # pymorphy3
        morph_start = time.perf_counter()
        self.morph = pymorphy3.MorphAnalyzer()

        # Прогрев: первые обращения к pymorphy3 медленнее
        self.morph.word_is_known("тест")
        self.morph.parse("абвгдежз")

        self.morph_time = time.perf_counter() - morph_start

        # ИБ-словарь: точные формы и леммы (для "коннектился" -> "коннектиться")
        self.ib_words = self.load_ib_words()
        self.dictionary_dirty = False   # словарь изменился - нужно сохранить

        if not self.ib_words:
            self.ib_words = set(SEED_TERMS)
            self.dictionary_dirty = True

        self.ib_lemmas = {
            self.lemma(w) for w in self.ib_words if CYRILLIC_ONLY.fullmatch(w)
        }

        self.candidates = self.load_candidates()

        self.promoted = []              # слова, перенесённые в словарь за сессию
        self.candidates_dirty = False   # кандидаты изменились - нужно сохранить

        # Кэш результатов: слово (как написано) -> (статус, исправление)
        self.cache = {}

        # Hunspell
        self.hunspell_calls = 0
        self.hunspell_calls_time = 0.0

        hunspell_start = time.perf_counter()

        os.environ["PATH"] = (
            str(HUNSPELL_EXE.parent) + os.pathsep + os.environ.get("PATH", "")
        )

        self.hunspell = subprocess.Popen(
            [str(HUNSPELL_EXE), "-a", "-d", str(HUNSPELL_DIC.with_suffix(""))],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding=HUNSPELL_ENCODING,
            errors="replace",
            bufsize=1
        )

        # Строка-приветствие Hunspell
        self.hunspell.stdout.readline()

        self.hunspell_time = time.perf_counter() - hunspell_start

        # Создаём файлы, если их ещё нет
        if not CANDIDATES_FILE.exists():
            self.candidates_dirty = True
        self.save()

        self.init_time = time.perf_counter() - start

    # ------------------------------------------------------------------
    # Загрузка / сохранение
    # ------------------------------------------------------------------

    def load_ib_words(self):
        if not IB_DICTIONARY.exists():
            return set()

        with open(IB_DICTIONARY, "r", encoding="utf-8") as file:
            return {line.strip().lower() for line in file if line.strip()}

    def load_candidates(self):
        if not CANDIDATES_FILE.exists():
            return {}

        try:
            with open(CANDIDATES_FILE, "r", encoding="utf-8") as file:
                data = json.load(file)
        except json.JSONDecodeError:
            backup = CANDIDATES_FILE.with_suffix(".json.bak")
            log.warning("candidates.json повреждён, копия: %s", backup)
            CANDIDATES_FILE.replace(backup)
            return {}

        # Слова, уже попавшие в словарь, из кандидатов убираем
        return {w: n for w, n in data.items() if w not in self.ib_words}

    def save(self):
        """Сохраняет изменения. Вызывается и автоматически при выходе из with."""
        start = time.perf_counter()

        if self.candidates_dirty:
            by_count = dict(
                sorted(self.candidates.items(), key=lambda x: (-x[1], x[0]))
            )
            write_text_atomic(
                CANDIDATES_FILE,
                json.dumps(by_count, ensure_ascii=False, indent=2),
            )
            self.candidates_dirty = False

        if self.dictionary_dirty:
            write_text_atomic(
                IB_DICTIONARY,
                "\n".join(sorted(self.ib_words)) + "\n",
            )
            self.dictionary_dirty = False

        return time.perf_counter() - start

    # ------------------------------------------------------------------
    # Hunspell
    # ------------------------------------------------------------------

    def hunspell_check(self, word):
        """Возвращает (слово_верно, список_подсказок)."""
        start = time.perf_counter()

        # "^" защищает от интерпретации слова как служебной команды
        self.hunspell.stdin.write("^" + word + "\n")
        self.hunspell.stdin.flush()

        # В режиме -a ответ заканчивается пустой строкой.
        # Читаем до неё, иначе ответы рассинхронизируются.
        lines = []
        while True:
            line = self.hunspell.stdout.readline()

            if line == "":
                raise RuntimeError("Процесс Hunspell завершился")

            line = line.rstrip("\r\n")

            if not line:
                break

            lines.append(line)

        self.hunspell_calls += 1
        self.hunspell_calls_time += time.perf_counter() - start

        result = lines[0] if lines else ""

        # "*" слово верно, "+" верно по корню, "-" верно как составное
        if result[:1] in ("*", "+", "-"):
            return True, []

        # "& слово N offset: подсказка1, подсказка2"
        if result.startswith("&") and ":" in result:
            suggestions = result.split(":", 1)[1].split(",")
            return False, [x.strip() for x in suggestions if x.strip()]

        return False, []

    # ------------------------------------------------------------------
    # ИБ-словарь и кандидаты
    # ------------------------------------------------------------------

    def lemma(self, word):
        return self.morph.parse(word)[0].normal_form

    def in_ib_by_lemma(self, key):
        """Проверка по лемме: 'коннектилась' -> 'коннектиться'."""
        return any(
            p.normal_form in self.ib_lemmas for p in self.morph.parse(key)[:3]
        )

    def find_in_ib(self, key, variants):
        """Опечатка ИБ-термина: ровно один термин словаря на расстоянии 1.
        'powershel' -> 'powershell', 'payloadd' -> 'payload'."""
        matches = variants & self.ib_words

        if len(matches) != 1:
            return None

        fix = next(iter(matches))

        # Без этого "https" исправлялся бы в "http", а "tasks" в "task"
        if STRICT_EDITS and not is_typo_edit(key, fix):
            return None

        return fix

    def add_candidate(self, key):
        """+1 встреча. На PROMOTE_THRESHOLD слово переезжает в ИБ-словарь."""
        count = self.candidates.get(key, 0) + 1
        self.candidates_dirty = True

        if count < PROMOTE_THRESHOLD:
            self.candidates[key] = count
            return

        self.candidates.pop(key, None)
        self.add_to_dictionary(key)

    def add_to_dictionary(self, key):
        self.ib_words.add(key)

        if CYRILLIC_ONLY.fullmatch(key):
            self.ib_lemmas.add(self.lemma(key))

        self.promoted.append(key)
        self.dictionary_dirty = True

    # ------------------------------------------------------------------
    # Проверка слов
    # ------------------------------------------------------------------

    def should_skip(self, text, start, word):
        if len(word) < 2:
            return True

        if any(c.isdigit() for c in word):
            return True

        # "кто-нибудь": частицу пропускаем, только если перед ней дефис
        if word.lower() in HYPHEN_PARTICLES and text[start - 1:start] == "-":
            return True

        return False

    def pick_correction(self, key, variants, suggestions):
        """Безопасное исправление из подсказок Hunspell (или None)."""
        # Подсказки идут от лучшей к худшей, берём первую подходящую
        for suggestion in suggestions:
            fix = suggestion.lower()

            # Ровно одна правка
            if fix not in variants:
                continue

            # Подсказка должна быть известна pymorphy3
            if not self.morph.word_is_known(fix):
                continue

            # Правка должна быть похожа на опечатку, а не на жаргон,
            # случайно близкий к обычному слову
            if STRICT_EDITS and not is_typo_edit(key, fix):
                continue

            return fix

        return None

    def analyze(self, word, key):
        """Полная проверка слова. Возвращает (статус, исправление)."""
        suggestions = []

        if not LATIN_ONLY.fullmatch(word):
            # Обычная лексика
            if self.morph.word_is_known(key):
                return VALID, None

            # Другая форма слова из ИБ-словаря
            if self.in_ib_by_lemma(key):
                return VALID, None

            valid, suggestions = self.hunspell_check(word)

            if valid:
                return VALID, None

        if len(key) < MIN_FIX_LEN:
            return CANDIDATE, None

        variants = edits1(key)

        fix = (
            self.find_in_ib(key, variants)
            or self.pick_correction(key, variants, suggestions)
        )

        if fix:
            return CORRECT, fix

        return CANDIDATE, None

    def check_word(self, word):
        key = word.lower()

        # 1. ИБ-словарь - самая быстрая проверка (set), поэтому первая
        if key in self.ib_words:
            return VALID, None

        # 2. Кэш
        if word in self.cache:
            result = self.cache[word]
        else:
            result = self.cache[word] = self.analyze(word, key)

        # Каждая встреча кандидата - это +1 к счётчику
        if result[0] == CANDIDATE:
            self.add_candidate(key)

        return result

    def check(self, text):
        """Возвращает (исправленный_текст, время)."""
        timer = time.perf_counter()

        # Защищённые диапазоны: URL, IP, хэши, CVE, домены
        protected = [(m.start(), m.end()) for m in PROTECTED.finditer(text)]

        replacements = []
        protected_index = 0

        for match in WORD.finditer(text):
            start, end = match.span()
            word = match.group()

            # Пропускаем диапазоны, которые закончились до слова
            while (
                protected_index < len(protected)
                and protected[protected_index][1] <= start
            ):
                protected_index += 1

            # Слово пересекается с защищённым диапазоном
            if (
                protected_index < len(protected)
                and protected[protected_index][0] < end
            ):
                continue

            if self.should_skip(text, start, word):
                continue

            status, fix = self.check_word(word)

            if status == CORRECT:
                replacements.append((start, end, match_case(word, fix)))

        # Собираем исправленный текст
        parts = []
        last = 0

        for start, end, replacement in replacements:
            parts.append(text[last:start])
            parts.append(replacement)
            last = end

        parts.append(text[last:])

        return "".join(parts), time.perf_counter() - timer

    # ------------------------------------------------------------------
    # Завершение работы
    # ------------------------------------------------------------------

    def close(self):
        self.save()

        if self.hunspell.poll() is None:
            try:
                self.hunspell.stdin.close()
            except Exception:
                pass
            self.hunspell.terminate()
            self.hunspell.wait()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


# ----------------------------------------------------------------------
# Flask API: POST /check_rus, streaming NDJSON (one JSON object per word)
# ----------------------------------------------------------------------

app = Flask(__name__)
checker = None
checker_lock = threading.Lock()
wordnet_lemmatizer = WordNetLemmatizer() if WordNetLemmatizer else None


def get_lemma(word):
    """Лемма для русского через pymorphy3, для английского — через WordNet."""
    if CYRILLIC_ONLY.fullmatch(word):
        return checker.lemma(word.lower())

    if LATIN_ONLY.fullmatch(word):
        if wordnet_lemmatizer is not None:
            try:
                # WordNet по умолчанию рассматривает слово как существительное.
                return wordnet_lemmatizer.lemmatize(word.lower())
            except LookupError:
                log.warning(
                    "Корпус WordNet не найден. Выполните: "
                    "python -c \"import nltk; nltk.download('wordnet')\""
                )
        # Явный fallback: без WordNet полноценная английская лемматизация недоступна.
        return word.lower()

    return word.lower()


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "spellchecker"})


@app.post("/check_rus")
def check_words():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("words"), list):
        return jsonify({"error": "Ожидается JSON-объект с массивом words"}), 400

    words = payload["words"]
    for i, item in enumerate(words):
        if not isinstance(item, dict) or not isinstance(item.get("text"), str):
            return jsonify({"error": f"words[{i}] должен содержать строковое поле text"}), 400
        if not isinstance(item.get("start"), int) or not isinstance(item.get("end"), int):
            return jsonify({"error": f"words[{i}] должен содержать целочисленные start и end"}), 400

    @stream_with_context
    def generate():
        for item in words:
            original = item["text"]
            start = item["start"]
            end = item["end"]

            # Один SpellChecker и один процесс Hunspell используются сервером.
            # Блокировка защищает кэш, счётчики кандидатов и протокол stdin/stdout Hunspell.
            with checker_lock:
                status, fix = checker.check_word(original)
                lemma_source = fix if status == CORRECT and fix else original
                lemma = get_lemma(lemma_source)
                output_text = match_case(original, fix) if status == CORRECT and fix else original
                checker.save()

            result = {
                "start": start,
                "end": end,
                "text": output_text,
                "lemma": lemma,
                "ib": status,
            }
            if status == CORRECT and fix:
                result["original"] = original

            yield json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n"

    return Response(generate(), content_type="application/x-ndjson; charset=utf-8")


if __name__ == "__main__":
    # Инициализация один раз на весь срок жизни сервера.
    checker = SpellChecker()
    print(f"Spellchecker initialized in {checker.init_time:.4f} sec.")
    print("Flask API: http://127.0.0.1:8092/check_rus")
    try:
        app.run(host="127.0.0.1", port=8092, threaded=True, use_reloader=False)
    finally:
        checker.close()
