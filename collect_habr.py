"""
Пост берём, если:
  1. он в одном из ИБ-хабов (HUBS), либо
  2. у него есть тег из IB_TAGS (ТОЧНОЕ совпадение, не подстрока!)
     и в тексте достаточно ИБ-лексики (MIN_STEM_HITS).
"""

import html
import re
import sys
from collections import Counter

from datasets import load_dataset

DATASET = "bikingSolo/IlyaGusev_habr_subset"
OUT_FILE = "corpus_ib.txt"

# Хабы, которым доверяем полностью. "infosecurity" подтверждён в датасете;
# остальные добавляйте после `python build_corpus.py stats`.
HUBS = {"infosecurity"}

# Теги: точное совпадение, нижний регистр
IB_TAGS = {
    "информационная безопасность", "кибербезопасность", "инфобез", "иб",
    "безопасность", "защита информации", "защита данных",
    "уязвимости", "уязвимость", "эксплойты", "exploit", "0day", "cve",
    "вредоносное по", "вредоносные программы", "вирусы", "malware",
    "ransomware", "шифровальщики", "трояны", "ботнет", "botnet",
    "фишинг", "социальная инженерия", "утечки данных", "утечки информации",
    "взлом", "хакеры", "хакерские атаки", "кибератаки", "ddos", "dos-атаки",
    "пентест", "pentest", "тестирование на проникновение", "pentesting",
    "red team", "blue team", "ctf", "owasp", "xss", "sql injection",
    "sql-инъекции", "реверс-инжиниринг", "reverse engineering",
    "обратная разработка", "криптография", "шифрование", "cryptography",
    "антивирусы", "антивирус", "siem", "soc", "edr", "ids", "ips", "waf",
    "брандмауэр", "firewall", "vpn", "аутентификация", "авторизация",
    "двухфакторная аутентификация", "пароли", "kaspersky", "касперский",
    "positive technologies", "расследование инцидентов", "форензика",
    "компьютерная криминалистика", "mitre att&ck", "threat intelligence",
}

# Корни ИБ-лексики для проверки, что пост действительно про безопасность
IB_STEMS = (
    "уязвим", "атак", "вредонос", "шифр", "взлом", "хакер", "безопасн",
    "вирус", "эксплойт", "фишинг", "пароль", "аутентиф", "malware",
    "угроз", "троян", "малвар", "бэкдор", "инцидент", "утечк", "защит",
    "exploit", "payload", "ransomware", "sandbox", "brute", "phishing",
)
MIN_STEM_HITS = 8
MIN_TEXT_LEN = 800     # короткие посты почти без текста не нужны

# Комментарии: много сленга, но и больше шума
INCLUDE_COMMENTS = False


def clean_line(line):
    line = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", line)     # картинки
    line = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", line)  # [текст](ссылка) -> текст
    line = re.sub(r"`[^`]*`", " ", line)                  # инлайн-код
    line = re.sub(r"<[^>]+>", " ", line)                  # html-теги
    line = re.sub(r"https?://\S+", " ", line)             # голые ссылки
    line = re.sub(r"^[#>*\-\s]+", "", line)               # маркеры markdown
    return re.sub(r"\s+", " ", html.unescape(line)).strip()


def clean_text(text):
    text = re.sub(r"```.*?```", "\n", text, flags=re.S)   # блоки кода
    lines = (clean_line(x) for x in text.splitlines())

    # Оставляем строки с нормальным русским текстом
    return [x for x in lines if len(x) >= 20 and re.search(r"[А-Яа-яЁё]{3}", x)]


def stem_hits(text):
    text = text.lower()
    return sum(text.count(stem) for stem in IB_STEMS)


def is_ib_post(post, paragraphs):
    """Возвращает True, если пост про ИБ."""
    if HUBS & set(post["hubs"] or []):
        return True

    tags = {t.strip().lower() for t in (post["tags"] or [])}

    return bool(tags & IB_TAGS) and stem_hits(" ".join(paragraphs)) >= MIN_STEM_HITS


def show_stats(ds):
    """Какие хабы и теги встречаются в данных - чтобы подобрать HUBS и IB_TAGS."""
    all_hubs, ib_hubs, ib_tags = Counter(), Counter(), Counter()

    for post in ds:
        if post["language"] != "ru":
            continue

        hubs = post["hubs"] or []
        all_hubs.update(hubs)

        if HUBS & set(hubs):
            ib_hubs.update(hubs)
            ib_tags.update(t.strip().lower() for t in post["tags"] or [])

    print("Все хабы (топ-40):")
    print(all_hubs.most_common(40))
    print("\nХабы, которые встречаются ВМЕСТЕ с ИБ-хабом (кандидаты в HUBS):")
    print(ib_hubs.most_common(30))
    print("\nТеги постов из ИБ-хаба (кандидаты в IB_TAGS):")
    print(ib_tags.most_common(80))


def build(ds):
    posts = 0
    hub_stats = Counter()

    with open(OUT_FILE, "w", encoding="utf-8") as out:
        for post in ds:
            if post["language"] != "ru":
                continue

            paragraphs = clean_text(post["text_markdown"] or "")

            if sum(len(x) for x in paragraphs) < MIN_TEXT_LEN:
                continue

            if not is_ib_post(post, paragraphs):
                continue

            if INCLUDE_COMMENTS:
                for message in (post["comments"] or {}).get("message_html", []):
                    paragraphs += clean_text(message)

            out.write("\n".join([post["title"]] + paragraphs) + "\n\n")
            hub_stats.update(post["hubs"] or [])
            posts += 1

    print(f"Постов в {OUT_FILE}: {posts}")
    print("Хабы в выборке:", hub_stats.most_common(15))


def main():
    ds = load_dataset(DATASET, split="train")

    if len(sys.argv) > 1 and sys.argv[1] == "stats":
        show_stats(ds)
    else:
        build(ds)


if __name__ == "__main__":
    main()