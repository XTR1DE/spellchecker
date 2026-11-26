import time

import pymorphy_perplex as spellchecker

VERBOSE = False

TOKEN_RE = spellchecker.TOKEN_RE

SAMPLES = [('Аналитик работал на серевре и изучил логи.', 'Аналитик работал на сервере и изучил логи.'),
           ('Процес завершился с ошибкой.', 'Процесс завершился с ошибкой.'),
           ('Все события зафиксированны в журнале.', 'Все события зафиксированы в журнале.'),
           ('Пользователь ввёл пороль на сайте.', 'Пользователь ввёл пароль на сайте.'),
           ('Администратор заметил активнсоть в сети.', 'Администратор заметил активность в сети.'),
           ('Ошибкаа появилась после обновления агента.', 'Ошибка появилась после обновления агента.'),
           ('Паролль сбросили после инцидента.', 'Пароль сбросили после инцидента.'),
           ('Серверр не отвечал на запросы.', 'Сервер не отвечал на запросы.'),
           ('Пользователль получил уведомление о входе.', 'Пользователь получил уведомление о входе.'),
           ('Сканнер проверил архив перед запуском.', 'Сканер проверил архив перед запуском.'),
           ('Злоумышленник начал аттаку на веб-сервис.', 'Злоумышленник начал атаку на веб-сервис.'),
           ('Обнаруженно подозрительное событие в журнале.', 'Обнаружено подозрительное событие в журнале.'),
           ('Подключенние к VPN завершилось успешно.', 'Подключение к VPN завершилось успешно.'),
           ('Зараженый файл поместили в карантин.', 'Зараженный файл поместили в карантин.'),
           ('Вредоноссный процесс создал дочерний процесс.', 'Вредоносный процесс создал дочерний процесс.'),
           ('Событиее отправили в SIEM.', 'Событие отправили в SIEM.'),
           ('Обновленние сигнатур завершилось без ошибок.', 'Обновление сигнатур завершилось без ошибок.'),
           ('Расследованние инцидента продолжается.', 'Расследование инцидента продолжается.'),
           ('Компрометациия учётной записи подтверждена.', 'Компрометация учётной записи подтверждена.'),
           ('Безопасностть хоста проверили повторно.', 'Безопасность хоста проверили повторно.'),
           ('Клиентт повторно отправил запрос.', 'Клиент повторно отправил запрос.'),
           ('Пакетт содержит подозрительный payload.', 'Пакет содержит подозрительный payload.'),
           ('Модулль агента перезапустили.', 'Модуль агента перезапустили.'),
           ('Логгирование включено на сервере.', 'Логирование включено на сервере.'),
           ('Антивирусс заблокировал вложение.', 'Антивирус заблокировал вложение.'),
           ('Серверыы отвечали с задержкой.', 'Серверы отвечали с задержкой.'),
           ('Проверкаа контрольной суммы завершилась.', 'Проверка контрольной суммы завершилась.'),
           ('Незаметнно выполнить команду не удалось.', 'Незаметно выполнить команду не удалось.'),
           ('Аутентификацция завершилась ошибкой.', 'Аутентификация завершилась ошибкой.'),
           ('Шифровальщикк зашифровал тестовую папку.', 'Шифровальщик зашифровал тестовую папку.'),
           ('Троянн пытался закрепиться в системе.', 'Троян пытался закрепиться в системе.'),
           ('Скриптт записал результат в файл.', 'Скрипт записал результат в файл.'),
           ('Сетьь сегментировали после тревоги.', 'Сеть сегментировали после тревоги.'),
           ('Инцидентт передали второй линии поддержки.', 'Инцидент передали второй линии поддержки.'),
           ('Сеанс завершилсся после выхода пользователя.', 'Сеанс завершился после выхода пользователя.'),
           ('Файл заблокированн политикой безопасности.', 'Файл заблокирован политикой безопасности.'),
           ('Учётная запись скомпрометированна.', 'Учётная запись скомпрометирована.'),
           ('Данные были выгруженны на внешний узел.', 'Данные были выгружены на внешний узел.'),
           ('Злонамереный процесс пытался скрыться.', 'Злонамеренный процесс пытался скрыться.'),
           ('Сканированние завершилось через пять минут.', 'Сканирование завершилось через пять минут.'),
           ('Задачу повторнно передали аналитику.', 'Задачу повторно передали аналитику.'),
           ('Событиие добавили в отчёт расследования.', 'Событие добавили в отчёт расследования.'),
           ('На хосте обнаружили паппку с архивами.', 'На хосте обнаружили папку с архивами.'),
           ('Командда завершилась с кодом ошибки.', 'Команда завершилась с кодом ошибки.'),
           ('Восстановленние доступа одобрил администратор.',
            'Восстановление доступа одобрил администратор.'),
           ('Вредоноссное вложение удалили из почты.', 'Вредоносное вложение удалили из почты.'),
           ('Проверили целостностть резервной копии.', 'Проверили целостность резервной копии.'),
           ('Пользователь ввёл неправильный паролл.', 'Пользователь ввёл неправильный пароль.'),
           ('Агент отправил отчёт с ошибкой в логахх.', 'Агент отправил отчёт с ошибкой в логах.'),
           ('На сервере лежат креды тестовой учётки.', 'На сервере лежат креды тестовой учётки.'),
           ('Аналитик чекнул логи и приложил пруфы.', 'Аналитик чекнул логи и приложил пруфы.'),
           ('На тестовом стенде подняли шелл через уязвимый сервис.',
            'На тестовом стенде подняли шелл через уязвимый сервис.'),
           ('После брута учётку временно заблокировали.', 'После брута учётку временно заблокировали.'),
           ('Пентестер нашёл баг и подготовил PoC.', 'Пентестер нашёл баг и подготовил PoC.'),
           ('Команда сделала реверс образца в изолированной среде.',
            'Команда сделала реверс образца в изолированной среде.'),
           ('В дампе памяти сохранились хеши и токены.', 'В дампе памяти сохранились хеши и токены.'),
           ('Дежурный отметил фолс-позитив и закрыл алерт.', 'Дежурный отметил фолс-позитив и закрыл алерт.'),
           ('Таск перенесли в другой спринт после ревью.', 'Таск перенесли в другой спринт после ревью.'),
           ('Фикс уже вмержили в мастер.', 'Фикс уже вмержили в мастер.'),
           ('Репа содержит конфиг с секретами.', 'Репа содержит конфиг с секретами.'),
           ('Креды не должны храниться в открытом виде.', 'Креды не должны храниться в открытом виде.'),
           ('Пользовательский токен утёк в дамп.', 'Пользовательский токен утёк в дамп.'),
           ('На хосте нашли стилер и дроппер.', 'На хосте нашли стилер и дроппер.'),
           ('В песочнице исследовали малварь и лоадер.', 'В песочнице исследовали малварь и лоадер.'),
           ('Инцидент передали на реверс-инжиниринг.', 'Инцидент передали на реверс-инжиниринг.'),
           ('Атакующий использовал фишинг и украл сессионные куки.',
            'Атакующий использовал фишинг и украл сессионные куки.'),
           ('Ботнет выполнял DDoS по команде оператора.', 'Ботнет выполнял DDoS по команде оператора.'),
           ('C2-сервер выдавал команды импланту.', 'C2-сервер выдавал команды импланту.'),
           ('Злоумышленник использовал Mimikatz и PowerShell.',
            'Злоумышленник использовал Mimikatz и PowerShell.'),
           ('Образец Emotet загрузил дополнительный модуль.',
            'Образец Emotet загрузил дополнительный модуль.'),
           ('WannaCry шифровал документы в тестовом образе.',
            'WannaCry шифровал документы в тестовом образе.'),
           ('NotPetya проверили на изолированной виртуальной машине.',
            'NotPetya проверили на изолированной виртуальной машине.'),
           ('В отчёте упомянут Cobalt Strike.', 'В отчёте упомянут Cobalt Strike.'),
           ('Внутри образца обнаружили AsyncRAT.', 'Внутри образца обнаружили AsyncRAT.'),
           ('RedLine проверили по сетевым индикаторам.', 'RedLine проверили по сетевым индикаторам.'),
           ('В каталоге обнаружены Remcos и XWorm.', 'В каталоге обнаружены Remcos и XWorm.'),
           ('Правило YARA сработало на подозрительном файле.',
            'Правило YARA сработало на подозрительном файле.'),
           ('Metasploit запускали только на тестовом стенде.',
            'Metasploit запускали только на тестовом стенде.'),
           ('PsExec упомянут в командной строке артефакта.', 'PsExec упомянут в командной строке артефакта.'),
           ('Impacket использовали в лабораторном сценарии.',
            'Impacket использовали в лабораторном сценарии.'),
           ('В отчёте фигурирует группировка APT28, также известная как Fancy Bear.',
            'В отчёте фигурирует группировка APT28, также известная как Fancy Bear.'),
           ('APT29 упоминается вместе с названием Cozy Bear.',
            'APT29 упоминается вместе с названием Cozy Bear.'),
           ('Lazarus Group упомянута в отчёте Threat Intelligence.',
            'Lazarus Group упомянута в отчёте Threat Intelligence.'),
           ('Sandworm фигурирует в сводке об атаке на инфраструктуру.',
            'Sandworm фигурирует в сводке об атаке на инфраструктуру.'),
           ('FIN7 упоминается в контексте фишинговых вложений.',
            'FIN7 упоминается в контексте фишинговых вложений.'),
           ('Black Basta оставила записку после шифрования.',
            'Black Basta оставила записку после шифрования.'),
           ('Scattered Spider упомянута в аналитической заметке.',
            'Scattered Spider упомянута в аналитической заметке.'),
           ('Lapsus$ упомянута в аналитической заметке.', 'Lapsus$ упомянута в аналитической заметке.'),
           ('Killnet заявила об атаке типа DDoS.', 'Killnet заявила об атаке типа DDoS.'),
           ('Anonymous разместили архив на публичном ресурсе.',
            'Anonymous разместили архив на публичном ресурсе.'),
           ('LockBit оставил записку с требованием выкупа.', 'LockBit оставил записку с требованием выкупа.'),
           ('ALPHV также известна как BlackCat.', 'ALPHV также известна как BlackCat.'),
           ('Дежурный SOC проверил алерт от EDR.', 'Дежурный SOC проверил алерт от EDR.'),
           ('Сигнатуру написали под YARA и Sigma.', 'Сигнатуру написали под YARA и Sigma.'),
           ('Suricata сгенерировала alert по DNS-трафику.', 'Suricata сгенерировала alert по DNS-трафику.'),
           ('Zeek сохранил conn.log для дальнейшего анализа.',
            'Zeek сохранил conn.log для дальнейшего анализа.'),
           ('BloodHound построил граф связей Active Directory.',
            'BloodHound построил граф связей Active Directory.'),
           ('В отчёте перечислены IOC, TTP и MITRE ATT&CK.', 'В отчёте перечислены IOC, TTP и MITRE ATT&CK.'),
           ('CVE-2021-44228 проверили отдельным сканером.', 'CVE-2021-44228 проверили отдельным сканером.'),
           ('Хеш образца сверили с VirusTotal.', 'Хеш образца сверили с VirusTotal.'),
           ('Оператор использовал прокси, VPN и Tor.', 'Оператор использовал прокси, VPN и Tor.'),
           ('Оператор получил доступ через RDP и закрепился в системе.',
            'Оператор получил доступ через RDP и закрепился в системе.')]


# ---------------------------------------------------------------------------
# Расстояние Левенштейна и метрики сходства
# ---------------------------------------------------------------------------

def levenshtein(a, b):
    """Расстояние Левенштейна для строк или последовательностей."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, item_a in enumerate(a, start=1):
        current = [i]
        for j, item_b in enumerate(b, start=1):
            cost = 0 if item_a == item_b else 1
            current.append(min(
                current[j - 1] + 1,  # вставка
                previous[j] + 1,  # удаление
                previous[j - 1] + cost,  # замена или совпадение
            ))
        previous = current
    return previous[-1]


def lcs_length(a, b):
    """Длина наибольшей общей подпоследовательности (с сохранением порядка)."""
    if len(a) < len(b):
        a, b = b, a
    previous = [0] * (len(b) + 1)
    for item_a in a:
        current = [0]
        for j, item_b in enumerate(b, start=1):
            if item_a == item_b:
                current.append(previous[j - 1] + 1)
            else:
                current.append(max(previous[j], current[j - 1]))
        previous = current
    return previous[-1]


def safe_div(numerator, denominator):
    return numerator / denominator if denominator else 0.0


def normalized_distance(distance, left_len, right_len):
    """Нормированное расстояние: Lev / max(длин двух последовательностей)."""
    denominator = max(left_len, right_len)
    return distance / denominator if denominator else 0.0


def prf_from_lcs(reference, hypothesis):
    """P/R/F1 по совпавшим элементам LCS; подходит для символов и токенов."""
    matches = lcs_length(reference, hypothesis)
    precision = safe_div(matches, len(hypothesis))
    recall = safe_div(matches, len(reference))
    f1 = safe_div(2 * precision * recall, precision + recall)
    return precision, recall, f1, matches


def tokens(text):
    return TOKEN_RE.findall(text)


def build_position_logs(source, logs):
    """Привязывает логи check() к позициям токенов исходного текста.

    check() создаёт запись только для слов, прошедших _should_check().
    Поскольку используется TOKEN_RE самого спеллчекера, позиции совпадают.
    """
    result = {}
    log_index = 0
    for position, word in enumerate(tokens(source)):
        if spellchecker._should_check(word):
            if log_index < len(logs):
                result[position] = logs[log_index]
            log_index += 1
    return result, log_index


def candidate_rank(info, expected_word):
    """Позиция правильного слова в отсортированном списке кандидатов; None — нет."""
    if not info:
        return None
    expected_normalized = spellchecker.normalize(expected_word)
    for rank, item in enumerate(info.get('candidates', []), start=1):
        candidate = item[0]
        if spellchecker.normalize(candidate) == expected_normalized:
            return rank
    return None


def print_section(title):
    print("\n" + "=" * 100)
    print(title)
    print("=" * 100)


def fmt_num(value, digits=4):
    return f"{value:.{digits}f}"


def fmt_pct(value):
    return f"{value * 100:.2f}%"


def print_comparison_table(rows):
    name_width = max(42, max(len(row[0]) for row in rows) + 2)
    print(f"{'Метрика':<{name_width}} {'ДО коррекции':>18} {'ПОСЛЕ коррекции':>20}")
    print("-" * (name_width + 40))
    for name, before, after in rows:
        print(f"{name:<{name_width}} {before:>18} {after:>20}")


def check_batch():
    """Проверка: NLL в батче должен совпадать с NLL при одиночном расчёте."""
    texts = [
        "Сервер не отвечал на запросы.",
        "Сервер.",
        "Аналитик работал на сервере и изучил логи.",
    ]
    together = spellchecker.nll_batch(texts)
    alone = [spellchecker.nll_batch([text])[0] for text in texts]
    difference = max(abs(a - b) for a, b in zip(together, alone))
    status = "OK" if difference < 1e-4 else "ПРОВЕРИТЬ"
    print(f"Проверка батчей: максимальная разница NLL {difference:.6f} [{status}]")


def evaluate_results(results):
    """Считает агрегированные метрики до и после коррекции."""
    sample_count = len(results)

    # Метрики расстояния и сходства текстов.
    sum_char_distance_before = 0
    sum_char_distance_after = 0
    sum_word_distance_before = 0
    sum_word_distance_after = 0
    sum_reference_chars = 0
    sum_reference_words = 0
    sum_char_lcs_before = 0
    sum_char_lcs_after = 0
    sum_word_lcs_before = 0
    sum_word_lcs_after = 0
    sum_input_chars = 0
    sum_output_chars = 0
    sum_reference_chars_for_length = 0
    sum_input_words = 0
    sum_output_words = 0
    sum_reference_words_for_length = 0
    normalized_char_before = []
    normalized_char_after = []
    normalized_word_before = []
    normalized_word_after = []
    exact_before = 0
    exact_after = 0
    better = worse = same = 0
    aligned_samples = 0
    unaligned_samples = []

    # Метрики качества самих исправлений.
    typo_total = 0
    clean_total = 0
    true_positive = 0
    false_positive = 0
    false_negative = 0
    true_negative = 0
    correct_fixes = 0
    wrong_fixes = 0
    false_corrections = 0
    missed_typos = 0
    typos_not_checked = 0
    typos_checked = 0
    typos_without_candidates = 0
    log_alignment_warnings = 0

    # Метрики ранжирования кандидатов.
    candidate_found = 0
    candidate_top1 = 0
    candidate_top3 = 0
    reciprocal_rank_sum = 0.0

    detailed_rows = []

    for sample_index, (source, expected, corrected, logs) in enumerate(results, start=1):
        source_tokens = tokens(source)
        expected_tokens = tokens(expected)
        corrected_tokens = tokens(corrected)

        # Символьные метрики считают пробелы и пунктуацию тоже.
        char_before = levenshtein(source, expected)
        char_after = levenshtein(corrected, expected)
        sum_char_distance_before += char_before
        sum_char_distance_after += char_after
        sum_reference_chars += len(expected)
        sum_input_chars += len(source)
        sum_output_chars += len(corrected)
        sum_reference_chars_for_length += len(expected)

        normalized_char_before.append(
            normalized_distance(char_before, len(source), len(expected))
        )
        normalized_char_after.append(
            normalized_distance(char_after, len(corrected), len(expected))
        )

        char_lcs_before = lcs_length(expected, source)
        char_lcs_after = lcs_length(expected, corrected)
        sum_char_lcs_before += char_lcs_before
        sum_char_lcs_after += char_lcs_after

        # Словные метрики работают по токенам TOKEN_RE; знаки пунктуации не учитываются.
        word_before = levenshtein(source_tokens, expected_tokens)
        word_after = levenshtein(corrected_tokens, expected_tokens)
        sum_word_distance_before += word_before
        sum_word_distance_after += word_after
        sum_reference_words += len(expected_tokens)
        sum_input_words += len(source_tokens)
        sum_output_words += len(corrected_tokens)
        sum_reference_words_for_length += len(expected_tokens)

        normalized_word_before.append(
            normalized_distance(word_before, len(source_tokens), len(expected_tokens))
        )
        normalized_word_after.append(
            normalized_distance(word_after, len(corrected_tokens), len(expected_tokens))
        )

        word_lcs_before = lcs_length(expected_tokens, source_tokens)
        word_lcs_after = lcs_length(expected_tokens, corrected_tokens)
        sum_word_lcs_before += word_lcs_before
        sum_word_lcs_after += word_lcs_after

        if source == expected:
            exact_before += 1
        if corrected == expected:
            exact_after += 1

        if char_after < char_before:
            better += 1
        elif char_after > char_before:
            worse += 1
        else:
            same += 1

        if corrected != expected or VERBOSE:
            detailed_rows.append((sample_index, source, expected, corrected, logs))

        # Словные метрики исправлений требуют взаимно-однозначного сопоставления
        # токенов по позициям. Если количество токенов поменялось, текстовые метрики
        # выше всё равно учитываются, но этот пример исключается из word-level PRF.
        if not (len(source_tokens) == len(expected_tokens) == len(corrected_tokens)):
            unaligned_samples.append(sample_index)
            continue

        aligned_samples += 1
        position_logs, consumed_logs = build_position_logs(source, logs)
        if consumed_logs != len(logs):
            log_alignment_warnings += 1

        for position, (original_word, expected_word, output_word) in enumerate(
                zip(source_tokens, expected_tokens, corrected_tokens)
        ):
            info = position_logs.get(position)

            if original_word != expected_word:
                typo_total += 1
                if info is None:
                    typos_not_checked += 1
                else:
                    typos_checked += 1
                    if info.get('best_word') is None:
                        typos_without_candidates += 1

                rank = candidate_rank(info, expected_word)
                if rank is not None:
                    candidate_found += 1
                    reciprocal_rank_sum += 1.0 / rank
                    if rank == 1:
                        candidate_top1 += 1
                    if rank <= 3:
                        candidate_top3 += 1

                if output_word == expected_word:
                    true_positive += 1
                    correct_fixes += 1
                else:
                    false_negative += 1
                    if output_word != original_word:
                        false_positive += 1
                        wrong_fixes += 1
                    else:
                        missed_typos += 1
            else:
                clean_total += 1
                if output_word == original_word:
                    true_negative += 1
                else:
                    false_positive += 1
                    false_corrections += 1

    # Агрегированные ошибки относительно эталона.
    cer_before = safe_div(sum_char_distance_before, sum_reference_chars)
    cer_after = safe_div(sum_char_distance_after, sum_reference_chars)
    wer_before = safe_div(sum_word_distance_before, sum_reference_words)
    wer_after = safe_div(sum_word_distance_after, sum_reference_words)

    # Микро Precision/Recall/F1 для символов и токенов по LCS.
    char_precision_before = safe_div(sum_char_lcs_before, sum_input_chars)
    char_recall_before = safe_div(sum_char_lcs_before, sum_reference_chars_for_length)
    char_f1_before = safe_div(
        2 * char_precision_before * char_recall_before,
        char_precision_before + char_recall_before,
    )
    char_precision_after = safe_div(sum_char_lcs_after, sum_output_chars)
    char_recall_after = safe_div(sum_char_lcs_after, sum_reference_chars_for_length)
    char_f1_after = safe_div(
        2 * char_precision_after * char_recall_after,
        char_precision_after + char_recall_after,
    )

    token_precision_before = safe_div(sum_word_lcs_before, sum_input_words)
    token_recall_before = safe_div(sum_word_lcs_before, sum_reference_words_for_length)
    token_f1_before = safe_div(
        2 * token_precision_before * token_recall_before,
        token_precision_before + token_recall_before,
    )
    token_precision_after = safe_div(sum_word_lcs_after, sum_output_words)
    token_recall_after = safe_div(sum_word_lcs_after, sum_reference_words_for_length)
    token_f1_after = safe_div(
        2 * token_precision_after * token_recall_after,
        token_precision_after + token_recall_after,
    )

    correction_precision = safe_div(true_positive, true_positive + false_positive)
    correction_recall = safe_div(true_positive, true_positive + false_negative)
    correction_f1 = safe_div(
        2 * correction_precision * correction_recall,
        correction_precision + correction_recall,
    )
    false_correction_rate = safe_div(false_corrections, clean_total)
    specificity = safe_div(true_negative, true_negative + false_corrections)

    candidate_coverage = safe_div(candidate_found, typo_total)
    candidate_top1_accuracy = safe_div(candidate_top1, typo_total)
    candidate_top3_accuracy = safe_div(candidate_top3, typo_total)
    candidate_mrr = safe_div(reciprocal_rank_sum, typo_total)

    # Вывод сравнения «до / после».
    rows = [
        ("Средняя длина текста (символы)", fmt_num(safe_div(sum_input_chars, sample_count), 2),
         fmt_num(safe_div(sum_output_chars, sample_count), 2)),
        ("Средняя длина текста (токены)", fmt_num(safe_div(sum_input_words, sample_count), 2),
         fmt_num(safe_div(sum_output_words, sample_count), 2)),
        ("Среднее расстояние Левенштейна (символы)",
         fmt_num(safe_div(sum_char_distance_before, sample_count), 3),
         fmt_num(safe_div(sum_char_distance_after, sample_count), 3)),
        ("Среднее расстояние Левенштейна (токены)",
         fmt_num(safe_div(sum_word_distance_before, sample_count), 3),
         fmt_num(safe_div(sum_word_distance_after, sample_count), 3)),
        ("Нормированное расстояние (символы, среднее)",
         fmt_num(safe_div(sum(normalized_char_before), sample_count), 5),
         fmt_num(safe_div(sum(normalized_char_after), sample_count), 5)),
        ("Сходство символов (1 - норм. расстояние)",
         fmt_num(1 - safe_div(sum(normalized_char_before), sample_count), 5),
         fmt_num(1 - safe_div(sum(normalized_char_after), sample_count), 5)),
        ("CER общий (сумма Lev / сумма символов эталона)",
         fmt_num(cer_before, 5), fmt_num(cer_after, 5)),
        ("WER общий (сумма Lev / сумма токенов эталона)",
         fmt_num(wer_before, 5), fmt_num(wer_after, 5)),
        ("Char precision (по LCS)", fmt_pct(char_precision_before), fmt_pct(char_precision_after)),
        ("Char recall (по LCS)", fmt_pct(char_recall_before), fmt_pct(char_recall_after)),
        ("Char F1 (по LCS)", fmt_pct(char_f1_before), fmt_pct(char_f1_after)),
        ("Token precision (по LCS)", fmt_pct(token_precision_before), fmt_pct(token_precision_after)),
        ("Token recall (по LCS)", fmt_pct(token_recall_before), fmt_pct(token_recall_after)),
        ("Token F1 (по LCS)", fmt_pct(token_f1_before), fmt_pct(token_f1_after)),
        ("Точные совпадения предложений", f"{exact_before}/{sample_count}",
         f"{exact_after}/{sample_count}"),
        ("Баланс длины (символы эталона минус текст)",
         fmt_num(sum_reference_chars_for_length - sum_input_chars, 0),
         fmt_num(sum_reference_chars_for_length - sum_output_chars, 0)),
    ]

    print_section("СРАВНЕНИЕ ТЕКСТОВ ДО И ПОСЛЕ КОРРЕКЦИИ")
    print_comparison_table(rows)

    print_section("ИЗМЕНЕНИЕ КАЧЕСТВА ТЕКСТОВ")
    print(f"Текстов стало ближе к эталону:       {better}")
    print(f"Текстов стало дальше от эталона:     {worse}")
    print(f"Без изменения расстояния:            {same}")
    print(f"Среднее улучшение Lev (символы):     "
          f"{safe_div(sum_char_distance_before - sum_char_distance_after, sample_count):+.3f}")
    print(f"Среднее улучшение Lev (токены):      "
          f"{safe_div(sum_word_distance_before - sum_word_distance_after, sample_count):+.3f}")
    print(f"Общее улучшение CER:                 {cer_before - cer_after:+.5f}")
    print(f"Общее улучшение WER:                 {wer_before - wer_after:+.5f}")

    print_section("КАЧЕСТВО ИСПРАВЛЕНИЙ ПО СЛОВАМ")
    print(f"Проверено примеров с одинаковым числом токенов: {aligned_samples}/{sample_count}")
    if unaligned_samples:
        print(f"Пропущены для позиционных метрик (разная длина токенов): {unaligned_samples}")
    if log_alignment_warnings:
        print(f"Предупреждений при сопоставлении логов: {log_alignment_warnings}")
    print(f"Реальных опечаток в эталонной разметке:           {typo_total}")
    print(f"Правильно исправлено:                            {correct_fixes}")
    print(f"Исправлено неправильным вариантом:                {wrong_fixes}")
    print(f"Опечаток оставлено без изменения:                 {missed_typos}")
    print(f"Опечаток не дошло до проверки (_should_check):     {typos_not_checked}")
    print(f"Проверено опечаток:                               {typos_checked}")
    print(f"Проверено, но кандидатов не было:                 {typos_without_candidates}")
    print(f"Правильных слов в исходных текстах:               {clean_total}")
    print(f"Ложных исправлений правильных слов:               {false_corrections}")
    print(f"Правильных слов оставлено без изменений:           {true_negative}")
    print("-" * 64)
    print(f"Precision исправлений: {fmt_pct(correction_precision)}")
    print(f"Recall исправлений:    {fmt_pct(correction_recall)}")
    print(f"F1 исправлений:        {fmt_pct(correction_f1)}")
    print(f"False Correction Rate: {fmt_pct(false_correction_rate)}")
    print(f"Specificity:           {fmt_pct(specificity)}")

    print_section("КАЧЕСТВО ГЕНЕРАЦИИ И РАНЖИРОВАНИЯ КАНДИДАТОВ")
    print(f"Покрытие: правильный вариант есть среди кандидатов: {fmt_pct(candidate_coverage)} "
          f"({candidate_found}/{typo_total})")
    print(f"Top-1 Accuracy (от всех опечаток):                 {fmt_pct(candidate_top1_accuracy)} "
          f"({candidate_top1}/{typo_total})")
    print(f"Top-3 Accuracy (от всех опечаток):                 {fmt_pct(candidate_top3_accuracy)} "
          f"({candidate_top3}/{typo_total})")
    print(f"MRR (от всех опечаток):                            {fmt_num(candidate_mrr, 4)}")

    if detailed_rows:
        print_section("ТЕКСТЫ С РАСХОЖДЕНИЯМИ С ЭТАЛОНОМ")
        for sample_index, source, expected, corrected, logs in detailed_rows:
            print(f"\n[{sample_index}] ИСХОДНЫЙ:  {source}")
            print(f"    ЭТАЛОН:    {expected}")
            print(f"    РЕЗУЛЬТАТ:  {corrected}")
            if VERBOSE:
                for info in logs:
                    if info.get('best_word') is None:
                        print(f"      {info['word']}: подходящих вариантов нет")
                    else:
                        decision = "ИСПРАВЛЕНО" if info['fixed'] else "оставлено"
                        print(f"      {info['word']}: {decision}; лучший вариант: "
                              f"{info['best_word']}; gain={info['gain']:+.3f}")
                        for candidate, score, gain in info.get('candidates', [])[:5]:
                            print(f"          {candidate:<24} NLL={score:8.3f} gain={gain:+.3f}")

    return {
        'typos': typo_total,
        'correct_fixes': correct_fixes,
        'wrong_fixes': wrong_fixes,
        'false_corrections': false_corrections,
        'precision': correction_precision,
        'recall': correction_recall,
        'f1': correction_f1,
        'cer_before': cer_before,
        'cer_after': cer_after,
        'wer_before': wer_before,
        'wer_after': wer_after,
    }


def main():
    start_load = time.perf_counter()
    spellchecker.load_model()
    load_time = time.perf_counter() - start_load

    check_batch()

    results = []
    start_check = time.perf_counter()
    for source, expected in SAMPLES:
        corrected, logs = spellchecker.check(source)
        results.append((source, expected, corrected, logs))
    check_time = time.perf_counter() - start_check

    metrics = evaluate_results(results)

    total_tokens = sum(len(tokens(source)) for source, _ in SAMPLES)
    print_section("ПРОИЗВОДИТЕЛЬНОСТЬ")
    print(f"Время загрузки модели:                 {load_time:.2f} сек.")
    print(f"Время проверки всего набора:           {check_time:.2f} сек.")
    print(f"Среднее время обработки предложения:   "
          f"{safe_div(check_time, len(SAMPLES)):.3f} сек.")
    print(f"Среднее время обработки одного токена: "
          f"{safe_div(check_time, total_tokens) * 1000:.2f} мс.")
    print(f"Всего предложений:                     {len(SAMPLES)}")
    print(f"Всего токенов в исходных текстах:      {total_tokens}")

    print_section("КРАТКИЙ ИТОГ")
    print(f"CER:       {metrics['cer_before']:.5f} -> {metrics['cer_after']:.5f}")
    print(f"WER:       {metrics['wer_before']:.5f} -> {metrics['wer_after']:.5f}")
    print(f"Precision: {fmt_pct(metrics['precision'])}")
    print(f"Recall:    {fmt_pct(metrics['recall'])}")
    print(f"F1:        {fmt_pct(metrics['f1'])}")
    print(f"Правильно исправлено опечаток: {metrics['correct_fixes']}/{metrics['typos']}")
    print(f"Ложных исправлений правильных слов: {metrics['false_corrections']}")


if __name__ == "__main__":
    main()
