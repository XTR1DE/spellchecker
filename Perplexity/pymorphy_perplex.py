import re

import pymorphy3
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


MODEL = "ai-forever/rugpt3small_based_on_gpt2"
MARGIN = 3.0   # на сколько nats вариант должен быть лучше исходного слова
MIN_LEN = 4    # слова короче не проверяем
WINDOW = 150   # символов контекста слева и справа
BATCH = 16     # сколько текстов считаем за один проход модели

# Буквы, которые разрешено путать при поиске опечаток.
SUBST = {
    "а": "о",
    "о": "а",
    "е": "и",
    "и": "еы",
    "ы": "и",
    "л": "ь",
}

# Заполняются функцией load_model().
tokenizer = None
model = None
morph = None
bos = None


def load_model():
    """Загружает языковую модель и pymorphy3."""
    global tokenizer, model, morph, bos

    print("Загрузка модели...", flush=True)
    tokenizer = AutoTokenizer.from_pretrained(MODEL)
    model = AutoModelForCausalLM.from_pretrained(MODEL).eval()
    morph = pymorphy3.MorphAnalyzer()

    bos = tokenizer.bos_token_id
    if bos is None:
        bos = tokenizer.eos_token_id

    print("Модель загружена.\n")


def is_known(word):
    """Проверяет, знает ли pymorphy3 слово."""
    return morph.word_is_known(word.lower())


def nll_batch(texts):
    """Суммарный NLL каждого текста. Чем меньше значение, тем правдоподобнее текст."""
    result = []

    for i in range(0, len(texts), BATCH):
        chunk = texts[i:i + BATCH]
        ids = [[bos] + tokenizer(text, add_special_tokens=False).input_ids for text in chunk]

        # Выравниваем тексты по длине; mask не даёт padding попасть в сумму.
        size = max(len(x) for x in ids)
        input_ids = torch.tensor([x + [bos] * (size - len(x)) for x in ids])
        mask = torch.tensor([[1] * len(x) + [0] * (size - len(x)) for x in ids])

        with torch.no_grad():
            logits = model(input_ids, attention_mask=mask).logits[:, :-1]
        loss = torch.nn.functional.cross_entropy(
            logits.transpose(1, 2), input_ids[:, 1:], reduction="none"
        )
        result += (loss * mask[:, 1:]).sum(dim=1).tolist()

    return result


def variants(word):
    """Создаёт варианты слова с одной разрешённой правкой."""
    word = word.lower()
    result = set()

    for i, char in enumerate(word):
        # Поменять соседние буквы местами.
        if i + 1 < len(word) and char != word[i + 1]:
            result.add(word[:i] + word[i + 1] + char + word[i + 2:])

        # Удалить одну букву из пары одинаковых.
        if i > 0 and char == word[i - 1]:
            result.add(word[:i] + word[i + 1:])

        # Добавить повтор этой буквы.
        result.add(word[:i] + char + word[i:])

        # Заменить букву на одну из похожих.
        for replacement in SUBST.get(char, ""):
            result.add(word[:i] + replacement + word[i + 1:])

    result.discard(word)
    return result


def match_case(new, old):
    """Сохраняет общий регистр исходного слова."""
    if old.isupper():
        return new.upper()
    if old[:1].isupper():
        return new[:1].upper() + new[1:]
    return new


def decide_word(word, left, right):
    """Выбирает исправление слова. Возвращает (слово, подробности для тестов)."""
    candidates = variants(word)

    # pymorphy3 фильтрует русские варианты, но не латинские названия и термины.
    if not re.search(r"[A-Za-z]", word):
        candidates = {c for c in candidates if is_known(c)}

    candidates = sorted(match_case(c, word) for c in candidates)

    info = {
        "word": word,
        "best_word": None,
        "gain": None,
        "fixed": False,
        "original_nll": None,
        "candidates": [],  # (вариант, nll, выигрыш), лучший первым
    }
    if not candidates:
        return word, info

    # Исходное слово и все варианты считаем одним списком.
    texts = [left + w + right for w in [word] + candidates]
    original_nll, *nlls = nll_batch(texts)

    scores = sorted(zip(candidates, nlls), key=lambda item: item[1])
    best_word, best_nll = scores[0]
    gain = original_nll - best_nll

    info["best_word"] = best_word
    info["gain"] = gain
    info["fixed"] = gain >= MARGIN
    info["original_nll"] = original_nll
    info["candidates"] = [(w, score, original_nll - score) for w, score in scores]

    return (best_word if info["fixed"] else word), info


def trim_left(text):
    """Убирает неполное слово в начале контекста."""
    match = re.search(r"\s", text)
    return text[match.end():] if match else text


def trim_right(text):
    """Убирает неполное слово в конце контекста."""
    match = re.search(r"\s\S*$", text)
    return text[:match.start()] if match else text


def check(text):
    """Исправляет текст. Возвращает (текст, подробности по неизвестным словам)."""
    result = ""  # исправленный текст до текущего слова
    last_end = 0
    logs = []

    # Ищем слова на русском и английском языках.
    for match in re.finditer(r"[A-Za-zА-Яа-яЁё]+", text):
        start, end = match.span()
        result += text[last_end:start]
        word = match.group()

        if len(word) >= MIN_LEN and not is_known(word):
            left = result[-WINDOW:]
            if len(result) > WINDOW:
                left = trim_left(left)

            right = text[end:end + WINDOW]
            if end + WINDOW < len(text):
                right = trim_right(right)

            word, info = decide_word(word, left, right)
            logs.append(info)

        result += word
        last_end = end

    return result + text[last_end:], logs


if __name__ == "__main__":
    load_model()
    text = "Аналитик заметил подозрительный процес на серевре, а ПРОЦЕС запускался каждые минуты. На хосте нашли Mimikatz и powershel скрипт"
    corrected_text, logs = check(text)

    print(corrected_text)
    for item in logs:
        if item["fixed"]:
            print(f"  {item['word']} -> {item['best_word']} (выигрыш {item['gain']:+.2f})")