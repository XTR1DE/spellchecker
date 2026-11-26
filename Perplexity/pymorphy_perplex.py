import re

import pymorphy3
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


MODEL = "ai-forever/rugpt3small_based_on_gpt2"
MARGIN = 3.0
MARGIN_LATIN = 4.5
MARGIN_UNFILTERED = 1.5
MIN_LEN = 4
MIN_LEN_LATIN = 6
WINDOW = 80            # было 150 — seq_len падает ~в 2 раза
BATCH = 64             # было 32 — лучше утилизация CPU/GPU

SUBST = {
    "а": "о",
    "о": "а",
    "е": "и",
    "и": "еы",
    "ы": "и",
    "л": "ь",
}

MIXED = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X",
    "У": "Y", "К": "K", "М": "M", "Т": "T", "В": "B", "Н": "H",
}
MIXED_REVERSE = {v: k for k, v in MIXED.items()}

INSERT_CYR = "нстрлвкмдпзбгиеаоыу"
INSERT_LAT = "etaoinshrlcdumpbgfywkvxjqz"

tokenizer = None
model = None
morph = None
bos = None
pad = None
device = "cpu"

TOKEN_RE = re.compile(r"[A-Za-zА-Яа-яЁё0-9$-]+")


def load_model():
    """Загружает языковую модель и pymorphy3."""
    global tokenizer, model, morph, bos, pad, device

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Загрузка модели (устройство: {device})...", flush=True)
    tokenizer = AutoTokenizer.from_pretrained(MODEL)
    model = AutoModelForCausalLM.from_pretrained(MODEL).eval().to(device)
    morph = pymorphy3.MorphAnalyzer()

    bos = tokenizer.bos_token_id
    if bos is None:
        bos = tokenizer.eos_token_id
    pad = tokenizer.pad_token_id
    if pad is None:
        pad = bos

    print("Модель загружена.\n")


def normalize(word):
    return word.lower().replace("ё", "е")


def is_known(word):
    return morph.word_is_known(normalize(word))



def nll_batch(texts):
    """Суммарный NLL каждого текста. inference_mode быстрее no_grad на CPU."""
    result = []
    with torch.inference_mode():
        for i in range(0, len(texts), BATCH):
            chunk = texts[i:i + BATCH]
            ids = [[bos] + tokenizer(t, add_special_tokens=False).input_ids for t in chunk]

            size = max(len(x) for x in ids)
            input_ids = torch.tensor(
                [x + [pad] * (size - len(x)) for x in ids], device=device
            )
            mask = torch.tensor(
                [[1] * len(x) + [0] * (size - len(x)) for x in ids], device=device
            )

            logits = model(input_ids, attention_mask=mask).logits[:, :-1]
            loss = torch.nn.functional.cross_entropy(
                logits.transpose(1, 2), input_ids[:, 1:], reduction="none"
            )
            result += (loss * mask[:, 1:]).sum(dim=1).tolist()

    return result


def variants(word):
    word_l = word.lower()
    is_latin = bool(re.search(r"[A-Za-z]", word_l))
    result = set()

    for i, char in enumerate(word_l):
        for repl in (MIXED.get(char), MIXED_REVERSE.get(char)):
            if repl:
                result.add(word_l[:i] + repl + word_l[i + 1:])

    for i, char in enumerate(word_l):
        if i + 1 < len(word_l) and char != word_l[i + 1]:
            result.add(word_l[:i] + word_l[i + 1] + char + word_l[i + 2:])

        if i > 0 and char == word_l[i - 1]:
            result.add(word_l[:i] + word_l[i + 1:])

        result.add(word_l[:i] + char + word_l[i:])

        min_len = MIN_LEN_LATIN if is_latin else MIN_LEN
        if len(word_l) >= min_len:
            alphabet = INSERT_LAT if is_latin else INSERT_CYR
            for extra in alphabet:
                result.add(word_l[:i] + extra + word_l[i:])

        if not is_latin:
            for replacement in SUBST.get(char, ""):
                result.add(word_l[:i] + replacement + word_l[i + 1:])

    result.discard(word_l)
    return result


def safe_variants(word):
    """Только «безопасные» правки для второго прохода (unfiltered).

    Дубль, перестановка, замена по SUBST. Без вставок — их слишком много,
    и правильный вариант почти всегда либо known (→ filtered), либо
    является результатом удаления дубля.
    """
    word_l = word.lower()
    is_latin = bool(re.search(r"[A-Za-z]", word_l))
    result = set()

    for i, char in enumerate(word_l):
        if i + 1 < len(word_l) and char != word_l[i + 1]:
            result.add(word_l[:i] + word_l[i + 1] + char + word_l[i + 2:])
        if i > 0 and char == word_l[i - 1]:
            result.add(word_l[:i] + word_l[i + 1:])
        if not is_latin:
            for replacement in SUBST.get(char, ""):
                result.add(word_l[:i] + replacement + word_l[i + 1:])

    result.discard(word_l)
    return result


def match_case(new, old):
    if old.isupper():
        return new.upper()
    if old[:1].isupper():
        return new[:1].upper() + new[1:]
    return new


def _finalize(info, candidates, original_nll, nlls, margin):
    scores = sorted(zip(candidates, nlls), key=lambda item: item[1])
    best_word, best_nll = scores[0]
    gain = original_nll - best_nll

    info["best_word"] = best_word
    info["gain"] = gain
    info["fixed"] = gain >= margin
    info["original_nll"] = original_nll
    info["candidates"] = [(w, score, original_nll - score) for w, score in scores]


def _split_candidates(word):
    """filtered — то, что знает pymorphy3. unfiltered — только безопасные правки."""
    vs = variants(word)
    is_latin = bool(re.search(r"[A-Za-z]", word))

    if is_latin:
        filtered_set = vs
        unfiltered_set = set()
    else:
        filtered_set = {c for c in vs if is_known(c)}
        unfiltered_set = safe_variants(word) - filtered_set

    filtered = sorted({match_case(c, word) for c in filtered_set})
    unfiltered = sorted({match_case(c, word) for c in unfiltered_set})
    return filtered, unfiltered


def decide_word(word, left, right, extra_texts=None, extra_meta=None):
    filtered, unfiltered = _split_candidates(word)

    info = {
        "word": word,
        "best_word": None,
        "gain": None,
        "fixed": False,
        "original_nll": None,
        "candidates": [],
    }

    if extra_texts is not None:
        if not filtered and not unfiltered:
            return word, info
        extra_meta.append((word, left, right, filtered, unfiltered, info))
        extra_texts.append(left + word + right)
        for c in filtered:
            extra_texts.append(left + c + right)
        return word, info

    if not filtered and not unfiltered:
        return word, info

    is_latin = bool(re.search(r"[A-Za-z]", word))
    base_margin = MARGIN_LATIN if is_latin else MARGIN

    texts1 = [left + word + right] + [left + c + right for c in filtered]
    nlls1 = nll_batch(texts1)
    orig = nlls1[0]
    info["original_nll"] = orig

    if filtered:
        _finalize(info, filtered, orig, nlls1[1:], base_margin)

    if not info["fixed"] and unfiltered:
        texts2 = [left + c + right for c in unfiltered]
        nlls2 = nll_batch(texts2)
        _finalize(info, unfiltered, orig, nlls2, base_margin * MARGIN_UNFILTERED)

    return (info["best_word"] if info["fixed"] else word), info


def flush_batch(extra_texts, extra_meta):
    if not extra_texts:
        return

    nlls1 = nll_batch(extra_texts)
    pos = 0
    need_second = []

    for idx, (word, left, right, filtered, unfiltered, info) in enumerate(extra_meta):
        orig = nlls1[pos]
        pos += 1
        cand = nlls1[pos:pos + len(filtered)]
        pos += len(filtered)

        is_latin = bool(re.search(r"[A-Za-z]", word))
        margin = MARGIN_LATIN if is_latin else MARGIN
        info["original_nll"] = orig

        if filtered:
            _finalize(info, filtered, orig, cand, margin)

        if not info["fixed"] and unfiltered:
            need_second.append((idx, orig))

    if not need_second:
        return

    texts2 = []
    for idx, _orig in need_second:
        _w, left, right, _f, unfiltered, _info = extra_meta[idx]
        for c in unfiltered:
            texts2.append(left + c + right)

    nlls2 = nll_batch(texts2)
    pos = 0
    for idx, orig in need_second:
        word, _left, _right, _f, unfiltered, info = extra_meta[idx]
        cand = nlls2[pos:pos + len(unfiltered)]
        pos += len(unfiltered)

        is_latin = bool(re.search(r"[A-Za-z]", word))
        margin = (MARGIN_LATIN if is_latin else MARGIN) * MARGIN_UNFILTERED
        _finalize(info, unfiltered, orig, cand, margin)


def trim_left(text):
    match = re.search(r"\s", text)
    return text[match.end():] if match else text


def trim_right(text):
    match = re.search(r"\s\S*$", text)
    return text[:match.start()] if match else text


def _should_check(word):
    if re.search(r"[0-9$\-.]", word):
        return False
    is_latin = bool(re.search(r"[A-Za-z]", word))
    min_len = MIN_LEN_LATIN if is_latin else MIN_LEN
    if len(word) < min_len:
        return False
    if word.isupper():
        return False
    if is_known(word):
        return False
    return True


def check(text):
    logs = []
    extra_texts = []
    extra_meta = []

    result = ""
    last_end = 0
    for match in TOKEN_RE.finditer(text):
        start, end = match.span()
        result += text[last_end:start]
        word = match.group()

        if _should_check(word):
            left = result[-WINDOW:]
            if len(result) > WINDOW:
                left = trim_left(left)
            right = text[end:end + WINDOW]
            if end + WINDOW < len(text):
                right = trim_right(right)
            _, info = decide_word(word, left, right, extra_texts, extra_meta)
            logs.append(info)

        result += word
        last_end = end

    flush_batch(extra_texts, extra_meta)

    if logs:
        result2 = ""
        last_end = 0
        log_iter = iter(logs)
        for match in TOKEN_RE.finditer(text):
            start, end = match.span()
            result2 += text[last_end:start]
            word = match.group()

            if _should_check(word):
                info = next(log_iter)
                if info["fixed"]:
                    word = info["best_word"]

            result2 += word
            last_end = end
        result = result2 + text[last_end:]
    else:
        result = result + text[last_end:]

    return result, logs


if __name__ == "__main__":
    load_model()

    text = (
        "Срочно: заметил подозрительный процес в диспетчере задач. "
        "Родитель - powershel.exe из temp. Креды пользователя в дампе lsass. "
        "Пользователь ввел паролль и получил ошбку. Через пару минут алерт от EDR. "
        "Хеш на VirusTotal - 47/72, семейство RedLine. "
        "IOC: 192.168.1.55, домен evil-c2.com. "
        "На хосте нашли стилер и дроппер AsyncRAT. "
        "Сделал реверс, в песочнице тихо. Может фолс-позитив, но лучше перепроверить. "
        "Атакующий использовал MITRE T1059.001 и T1003.001. "
        "Логи за сутки поднял. Нужен таск на проверку и фикс правила YARA. "
        "Репа с конфигом возможно скомпрометированна."
    )

    corrected_text, logs = check(text)

    print("=" * 72)
    print("ИСХОДНЫЙ ТЕКСТ")
    print("=" * 72)
    print(text)

    print("\n" + "=" * 72)
    print("ИСПРАВЛЕННЫЙ ТЕКСТ")
    print("=" * 72)
    print(corrected_text)

    print("\n" + "=" * 72)
    print("ЧТО ИСПРАВЛЕНО")
    print("=" * 72)
    fixed = [i for i in logs if i["fixed"]]
    if not fixed:
        print("  (ничего)")
    for item in fixed:
        print(f"  {item['word']} → {item['best_word']}  (выигрыш {item['gain']:+.2f})")

    print("\n" + "=" * 72)
    print("ЧТО ОСТАВЛЕНО (кандидаты были, но выигрыш ниже порога)")
    print("=" * 72)
    kept = [i for i in logs if not i["fixed"] and i["best_word"] is not None]
    if not kept:
        print("  (ничего)")
    for item in kept:
        print(f"  {item['word']:<20} лучший: {item['best_word']:<20} выигрыш {item['gain']:+.2f}")

    print("\n" + "=" * 72)
    print("ЧТО ПРОПУЩЕНО (кандидатов не было)")
    print("=" * 72)
    skipped = [i for i in logs if i["best_word"] is None]
    if not skipped:
        print("  (ничего)")
    for item in skipped:
        print(f"  {item['word']}")