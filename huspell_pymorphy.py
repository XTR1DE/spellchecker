import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path

import pymorphy3


logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")
log = logging.getLogger("spellchecker")

BASE_DIR = Path(__file__).resolve().parent

HUNSPELL_EXE = BASE_DIR / "Hunspell" / "bin" / "hunspell.exe"
HUNSPELL_DIC = BASE_DIR / "hunspell-1.7.3" / "ru_RU.dic"

# Должна совпадать со строкой SET в ru_RU.aff (koi8-r или utf-8)
HUNSPELL_ENCODING = "koi8-r"

IB_DICTIONARY = BASE_DIR / "data" / "ib_dictionary.txt"
CANDIDATES_FILE = BASE_DIR / "data" / "candidates.json"

# True  - автоисправляем только "похожие на опечатки" правки
#         (перестановка, удвоение/раздвоение буквы, соседняя клавиша,
#         путаница а/о и е/и). Меньше ложных исправлений жаргона.
# False - исправляем любую правку на расстоянии 1.
STRICT_EDITS = True


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

# Дефис и апостроф — разделители: "powershell-скрипт" даст два токена
WORD = re.compile(r"[A-Za-zА-Яа-яЁё0-9]+")

LATIN_ONLY = re.compile(r"[A-Za-z]+")

# Частицы после дефиса, которые pymorphy3 отдельно не знает
HYPHEN_PARTICLES = {
    "то", "либо", "нибудь", "таки", "ка", "де", "кась", "с", "тка"
}


# ----------------------------------------------------------------------
# Правдоподобные типы опечаток
# ----------------------------------------------------------------------

KEYBOARD_ROWS = ["йцукенгшщзхъ", "фывапролджэ", "ячсмитьбю"]

# Пары гласных, которые часто путают при письме
VOWEL_PAIRS = {frozenset("ао"), frozenset("еи")}


def build_keyboard_neighbors():
    """Соседние клавиши раскладки ЙЦУКЕН."""
    pos = {}

    for r, row in enumerate(KEYBOARD_ROWS):
        for c, ch in enumerate(row):
            pos[ch] = (r, c)

    neighbors = {ch: set() for ch in pos}

    for ch, (r, c) in pos.items():
        for ch2, (r2, c2) in pos.items():
            if ch == ch2:
                continue

            # Та же строка, соседняя клавиша
            if r2 == r and abs(c2 - c) == 1:
                neighbors[ch].add(ch2)

            # Нижняя строка сдвинута на пол-клавиши:
            # клавиша (r+1, c) касается (r, c) и (r, c+1)
            if r2 == r + 1 and c2 in (c - 1, c):
                neighbors[ch].add(ch2)
                neighbors[ch2].add(ch)

    return neighbors


KB_NEIGHBORS = build_keyboard_neighbors()


def is_typo_edit(wrong, right):

    la, lb = len(wrong), len(right)

    # Одинаковая длина: замена или перестановка
    if la == lb:
        diffs = [i for i in range(la) if wrong[i] != right[i]]

        if len(diffs) == 1:
            a, b = wrong[diffs[0]], right[diffs[0]]
            return (
                b in KB_NEIGHBORS.get(a, ())
                or frozenset((a, b)) in VOWEL_PAIRS
            )

        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            i, j = diffs
            return wrong[i] == right[j] and wrong[j] == right[i]

        return False

    # В правильном слове на одну букву больше
    if lb == la + 1:
        longer, shorter = right, wrong
    # В неправильном слове на одну букву больше
    elif la == lb + 1:
        longer, shorter = wrong, right
    else:
        return False

    for j in range(len(longer)):
        if longer[:j] + longer[j + 1:] != shorter:
            continue

        # Лишняя/пропущенная буква дублирует соседнюю
        if j > 0 and longer[j] == longer[j - 1]:
            return True

        if j + 1 < len(longer) and longer[j] == longer[j + 1]:
            return True

    return False


def match_case(src, repl):
    """Подгоняет регистр подсказки под исходное слово."""
    if len(src) > 1 and src.isupper():
        return repl.upper()
    if src[:1].isupper():
        return repl[:1].upper() + repl[1:]
    return repl


class SpellChecker:

    def __init__(self):
        start = time.perf_counter()

        self.ib_words = self.load_words(IB_DICTIONARY)
        self.candidates = self.load_candidates()

        # Автоисправления за сессию: слово -> исправление
        self.corrections = {}

        # Статистика вызовов Hunspell
        self.hunspell_calls = 0
        self.hunspell_calls_time = 0.0

        morph_start = time.perf_counter()
        self.morph = pymorphy3.MorphAnalyzer()

        # Прогрев: первые обращения к pymorphy3 могут быть медленнее
        self.morph.word_is_known("тест")
        self.morph.parse("абвгдежз")

        self.morph_time = time.perf_counter() - morph_start

        hunspell_start = time.perf_counter()

        os.environ["PATH"] = (
            str(HUNSPELL_EXE.parent)
            + os.pathsep
            + os.environ.get("PATH", "")
        )

        self.hunspell = subprocess.Popen(
            [
                str(HUNSPELL_EXE),
                "-a",
                "-d",
                str(HUNSPELL_DIC.with_suffix(""))
            ],
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

        self.cache = {}

        self.init_time = time.perf_counter() - start

    # ------------------------------------------------------------------
    # Загрузка / сохранение
    # ------------------------------------------------------------------

    def load_words(self, path):
        if not path.exists():
            return set()

        with open(path, "r", encoding="utf-8") as file:
            return {
                line.strip().lower()
                for line in file
                if line.strip()
            }

    def load_candidates(self):
        if not CANDIDATES_FILE.exists():
            return {}

        with open(CANDIDATES_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    def save(self):
        start = time.perf_counter()

        CANDIDATES_FILE.parent.mkdir(parents=True, exist_ok=True)

        with open(CANDIDATES_FILE, "w", encoding="utf-8") as file:
            json.dump(
                self.candidates,
                file,
                ensure_ascii=False,
                indent=2
            )

        return time.perf_counter() - start

    # ------------------------------------------------------------------
    # Hunspell
    # ------------------------------------------------------------------

    def hunspell_check(self, word):
        start = time.perf_counter()

        # "^" защищает от интерпретации слова как служебной команды
        self.hunspell.stdin.write("^" + word + "\n")
        self.hunspell.stdin.flush()

        # В режиме -a после каждого ответа идёт пустая строка.
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

        if result[:1] in ("*", "+", "-"):
            return True, []

        if result.startswith("&") and ":" in result:
            suggestions = result.split(":", 1)[1]

            return False, [
                x.strip()
                for x in suggestions.split(",")
                if x.strip()
            ]

        return False, []

    # ------------------------------------------------------------------
    # Расстояние Дамерау-Левенштейна (OSA)
    # ------------------------------------------------------------------

    def damerau_levenshtein(self, a, b):
        if a == b:
            return 0

        if not a:
            return len(b)

        if not b:
            return len(a)

        previous_previous = None
        previous = list(range(len(b) + 1))

        for i, char_a in enumerate(a, 1):
            current = [i]

            for j, char_b in enumerate(b, 1):
                value = min(
                    current[j - 1] + 1,                      # вставка
                    previous[j] + 1,                         # удаление
                    previous[j - 1] + (char_a != char_b)     # замена
                )

                # Перестановка соседних символов
                if (
                    previous_previous is not None
                    and i > 1
                    and j > 1
                    and char_a == b[j - 2]
                    and a[i - 2] == char_b
                ):
                    value = min(value, previous_previous[j - 2] + 1)

                current.append(value)

            previous_previous = previous
            previous = current

        return previous[-1]

    def add_candidate(self, word):
        key = word.lower()
        self.candidates[key] = self.candidates.get(key, 0) + 1

    def in_ib_dictionary_by_lemma(self, word):
        """Проверка по лемме: 'коннектилась' -> 'коннектиться'."""
        for parse in self.morph.parse(word)[:3]:
            if parse.normal_form in self.ib_words:
                return True

        return False

    def should_skip(self, word):
        if len(word) < 2:
            return True

        if any(c.isdigit() for c in word):
            return True

        return False

    def pick_correction(self, key, suggestions):
        """Выбирает безопасное исправление из подсказок Hunspell."""

        # Подсказки идут от лучшей к худшей, берём первую подходящую
        for suggestion in suggestions:
            suggestion_key = suggestion.lower()

            # Подсказка должна быть известна pymorphy3
            if not self.morph.word_is_known(suggestion):
                continue

            # Для прототипа разрешаем только одну ошибку
            if self.damerau_levenshtein(key, suggestion_key) != 1:
                continue

            # Правка должна быть похожа на опечатку, а не на
            # жаргонное слово, случайно близкое к обычному
            if STRICT_EDITS and not is_typo_edit(key, suggestion_key):
                continue

            return suggestion_key

        return None

    def check_word(self, word):
        key = word.lower()

        # Кэш
        if key in self.cache:
            status, replacement = self.cache[key]

            if status == "candidate":
                self.add_candidate(key)

            return status, replacement

        # Частицы после дефиса
        if key in HYPHEN_PARTICLES:
            self.cache[key] = ("valid", None)
            return "valid", None

        # ИБ-словарь: точная форма
        if key in self.ib_words:
            self.cache[key] = ("valid", None)
            return "valid", None

        # Обычное слово
        if self.morph.word_is_known(word):
            self.cache[key] = ("valid", None)
            return "valid", None

        # ИБ-словарь: по лемме (только для неизвестных pymorphy3 слов)
        if self.in_ib_dictionary_by_lemma(word):
            self.cache[key] = ("valid", None)
            return "valid", None

        # Hunspell
        valid, suggestions = self.hunspell_check(word)

        if suggestions:
            log.debug("%s -> %s", word, suggestions)

        if valid:
            self.cache[key] = ("valid", None)
            return "valid", None

        best_candidate = self.pick_correction(key, suggestions)

        if best_candidate is not None:
            self.cache[key] = ("correct", best_candidate)
            self.corrections[key] = best_candidate
            return "correct", best_candidate

        # Подходящего исправления нет — кандидат в словарь
        self.add_candidate(key)
        self.cache[key] = ("candidate", None)

        return "candidate", None

    def check(self, text):
        timer = time.perf_counter()

        # Защищённые диапазоны (отсортированы и не пересекаются)
        protected = [
            (m.start(), m.end())
            for m in PROTECTED.finditer(text)
        ]

        replacements = []
        protected_index = 0

        for match in WORD.finditer(text):
            start_pos = match.start()
            end_pos = match.end()
            word = match.group()

            # Пропускаем диапазоны, которые закончились до слова
            while (
                protected_index < len(protected)
                and protected[protected_index][1] <= start_pos
            ):
                protected_index += 1

            # Слово пересекается с защищённым диапазоном
            if (
                protected_index < len(protected)
                and protected[protected_index][0] < end_pos
            ):
                continue

            if self.should_skip(word):
                continue

            status, replacement = self.check_word(word)

            if status == "correct":
                replacements.append(
                    (start_pos, end_pos, match_case(word, replacement))
                )

        # Собираем исправленный текст
        parts = []
        last = 0

        for start_pos, end_pos, replacement in replacements:
            parts.append(text[last:start_pos])
            parts.append(replacement)
            last = end_pos

        parts.append(text[last:])

        return "".join(parts), time.perf_counter() - timer

    # Завершение работы

    def close(self):
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


if __name__ == "__main__":

    text = """
В ходе расследования инцидента на одном из хостов корпоративной сети был замечен подозрительный powershell-скрипт, который запускался через планировщик задач. На серевре также нашли несколько странных файлов во временной директории и процес, который постоянно коннектился на внешний IP 185.23.41.17.
Первоначально SOC заметил алерт от EDR, после чего аналитик начал смотреть логи с SIEM. В логах были зафиксированны подозрительные коннекты и несколько попыток авторизации под учеткой администратора. Есть предположение, что атакующий сначала сделал брутфорс пароля, а потом получил доступ к хосту и начал латеральное перемещение по сети.
На машине обнаружили Mimikatz и несколько powershell-команд для дампа кредов. Также был найден подозрительный батник, который создавал persistence через registry run keys. После запуска батника малварь конектилась на C2 и передавала базовую инфу о системе.
Один из бинарников был отправлен на песочницу. YARA-правило сработало на сигнатуру, связанную с загрузчиком. После этого аналитик проверил хэш файла и сравнил его с данными из внутренней базы IOC.
В ходе дополнительного анализа были обнаружены новые процессы, запущенные от имени системной учетки. Один из процессов создавал дочерний процесс через cmd.exe, а затем запускал powershell с параметрами для скрытого выполнения команды. В командной строке использовался Base64-кодированный payload.
На другом хосте обнаружили подозрительный scheduled task, который запускал скрипт каждые 30 минут. В реестре были найдены дополнительные ключи автозапуска. Аналитик проверил HKCU и HKLM, после чего обнаружил несколько неизвестных записей в разделе Run.
Также были замечены попытки обращения к нескольким внешним доменам. Часть запросов шла через HTTP, а часть через HTTPS. Один из запросов содержал подозрительный URL: https://example.com/update.ps1. Другой запрос был направлен на домен cdn-update.example.net.
В сетевом трафике были замечены повторяющиеся подключения к адресу 192.168.10.25. Через несколько минут после входа пользователя на рабочую станцию появился новый сетевой коннект на внешний сервер. Соединение устанавливалось каждые несколько секунд, что может указывать на использование C2-канала.
При анализе DNS-логов были найдены многочисленные запросы к доменам, которые ранее не встречались в корпоративной сети. Несколько доменов имели необычно длинные поддомены. Также были обнаружены TXT-запросы, которые могли использоваться для передачи небольших фрагментов данных.
На рабочей станции пользователя были обнаружены файлы с расширениями .ps1, .bat, .vbs и .js. Один из VBS-скриптов находился в каталоге пользователя и запускался автоматически после входа в систему. Другой файл имел имя update.vbs, хотя ранее соответствующего программного обеспечения на компьютере не было.
В журнале событий Windows были найдены многочисленные события входа. Некоторые попытки авторизации завершились успешно, другие завершились ошибкой. Зафиксированны несколько неудачных попыток входа под учетными записями administrator и admin. После этого была обнаружена успешная авторизация с той же учеткой.
Аналитик проверил события 4624, 4625 и 4688, после чего сопоставил их со временем сетевых подключений. В результате удалось установить примерную последовательность действий атакующего.
На одном из серверов были обнаружены подозрительные службы. Служба запускалась автоматически при старте Windows и выполняла неизвестный бинарник из временной директории. Имя службы было похоже на название системного компонента, однако путь к исполняемому файлу отличался от стандартного.
Дополнительно был обнаружен пользовательский аккаунт, созданный незадолго до начала подозрительной активности. Учетная запись имела права, которые не требовались для выполнения обычных задач. После создания аккаунта были выполнены несколько команд для изменения групп и разрешений.
При анализе PowerShell-логов обнаружили команды для получения информации о пользователях, группах, процессах и сетевых соединениях. В частности, выполнялись Get-Process, Get-Service, Get-NetTCPConnection и Get-LocalUser. Некоторые команды были закодированы и запускались через powershell.exe.
В памяти одного из процессов был найден фрагмент, похожий на credential dump. Для дополнительной проверки был использован Volatility. Полученные артефакты показали наличие учетных данных, которые могли использоваться для дальнейшего перемещения по сети.
После получения доступа атакующий мог использовать RDP и SMB для подключения к другим хостам. В логах были замечены подключения к нескольким серверам через RDP. Также наблюдались обращения к административным шарам.
На файловом сервере обнаружили большое количество обращений к документам. Некоторые файлы были прочитаны непосредственно перед установлением новых сетевых соединений. Несколько архивов были созданы во временной директории, после чего переданы на внешний ресурс.
В ходе анализа был найден файл с SHA256:
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
Также был обнаружен MD5-хэш:
d41d8cd98f00b204e9800998ecf8427e
Для одного из файлов была найдена уязвимость CVE-2026-12345. Однако наличие CVE само по себе не подтверждает факт эксплуатации уязвимости. Аналитик дополнительно проверил журналы веб-сервера и сетевые события.
Среди возможных вариантов рассматриваются эксплуатация уязвимости, фишинг, подбор пароля, использование украденных учетных данных и выполнение вредоносного скрипта через PowerShell.
На почтовом сервере были обнаружены сообщения с подозрительными вложениями. Несколько пользователей получили письма с архивами и документами. Один из документов содержал макрос, который после открытия выполнял внешний powershell-командлет.
После открытия документа был создан временный файл, а затем запущен новый процесс. Через несколько секунд рабочая станция установила соединение с внешним сервером.
В другом случае пользователь перешел по ссылке из письма и ввел учетные данные на поддельной странице авторизации. Через некоторое время с этой учетной записи была выполнена успешная авторизация на внутреннем сервере.
Аналитик также проверил наличие persistence в профилях пользователей. Были просмотрены Startup-папки, registry run keys, scheduled tasks и службы Windows. В одном из профилей обнаружили неизвестный скрипт, который запускался при входе пользователя.
На Linux-сервере ситуация отличалась. Там были проверены cron, systemd units, SSH-ключи и bash history. В authorized_keys была найдена неизвестная строка, добавленная незадолго до начала инцидента.
В журналах SSH обнаружили множество неудачных попыток входа. После серии ошибок произошел успешный login с внешнего IP-адреса. Затем пользователь выполнил несколько команд для просмотра процессов, сетевых соединений и содержимого каталогов.
Были проверены команды ps aux, netstat, ss, who, last и uname. После этого на сервер был загружен неизвестный ELF-бинарник.
Файл был отправлен на sandbox. Во время динамического анализа бинарник создал новый процесс, изменил несколько файлов и попытался установить соединение с C2. YARA-правило сработало на сигнатуру, связанную с известным загрузчиком.
После завершения анализа были собраны IOC: IP-адреса, домены, URL, хэши файлов, имена процессов, пути к файлам и учетные записи. IOC были переданы команде SOC для дальнейшего мониторинга.
На следующем этапе специалисты проверили другие хосты сети. На нескольких машинах были найдены одинаковые файлы и похожие scheduled tasks. Однако часть совпадений оказалась легитимным программным обеспечением, поэтому эти события не были классифицированы как инциденты.
Некоторые пользователи сообщили о медленной работе компьютеров и появлении неизвестных окон командной строки. При проверке выяснилось, что в нескольких случаях причиной были обычные обновления программного обеспечения.
В финальном отчете необходимо отделить подтвержденные факты от предположений. Не каждое неизвестное слово, имя файла, домен или процесс является признаком компрометации. Аналитик должен учитывать контекст события, время возникновения, источник данных и связь с другими артефактами.
Итоговая гипотеза состоит в том, что первоначальный доступ мог быть получен через фишинговое письмо или подбор пароля. После получения доступа атакующий мог выполнить discovery, собрать учетные данные, установить persistence и начать латеральное перемещение. На следующем этапе мог использоваться C2-канал для управления скомпрометированным хостом.
Для проверки гипотезы необходимо сопоставить данные EDR, SIEM, Windows Event Logs, PowerShell logs, DNS logs, proxy logs, firewall logs и результаты анализа файлов.
Дополнительные подозрительные слова для проверки: серевре, процес, зафиксированны, конектилась, конектился, авторизацыя, подозрителный, обнаруженоо, процесы, учеткои, администраторр, powershel, mimikats, persistance, registri, conection, malvare, payloadd.
Нормальные слова для проверки: сервер, процесс, процессы, пользователь, администратор, учетная запись, авторизация, подключение, соединение, журнал, событие, файл, директория, система, сеть, команда, анализ, расследование, инцидент, уязвимость, эксплуатация, пароль, учетные данные.
ИБ-термины для проверки: SOC, EDR, SIEM, IOC, C2, YARA, Mimikatz, PowerShell, persistence, payload, sandbox, Volatility, RDP, SMB, SSH, DNS, HTTP, HTTPS, CVE, Base64, cron, systemd, registry, startup, scheduled task.
"""

    with SpellChecker() as checker:

        print("=" * 50)
        print("TIME\n")

        print(f"pymorphy3:  {checker.morph_time:.4f} сек.")
        print(f"Hunspell:   {checker.hunspell_time:.4f} сек.")
        print(f"INIT:       {checker.init_time:.4f} сек.")

        calls_before = checker.hunspell_calls
        calls_time_before = checker.hunspell_calls_time

        corrected, check_time = checker.check(text)

        print()
        print("=" * 50)
        print("RESULT\n")

        for x, y in zip(corrected.split(), text.split()):
            if x == y: continue
            print(f"{y} ------> {x}")

        print()

        save_time = checker.save()

        print()
        print("=" * 50)
        print("TIME\n")

        check_calls = checker.hunspell_calls - calls_before
        check_calls_time = checker.hunspell_calls_time - calls_time_before

        print(f"CHECK:      {check_time:.4f} сек.")
        print(f"SAVE:       {save_time:.4f} сек.")