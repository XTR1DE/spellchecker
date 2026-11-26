"""Тесты и метрики для huspell_pymorphy.SpellChecker.

Запуск из этой папки:
    python test_huspell_pymorphy.py

Тестовый запуск отключает обучение и не изменяет ib_dictionary.txt
и candidates.json.
"""

import time

from huspell_pymorphy import SpellChecker, VALID, WORD

# ----------------------------------------------------------------------
# Тестовый набор и метрики
# ----------------------------------------------------------------------

WORD_RE = WORD

# Общий тестовый набор: те же примеры, что и в perplex_test.py, плюс пример с RDP.
SAMPLES = [
    ('Аналитик работал на серевре и изучил логи.', 'Аналитик работал на сервере и изучил логи.'),
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
    ('Подключенние к сети завершилось успешно.', 'Подключение к сети завершилось успешно.'),
    ('Зараженый файл поместили в карантин.', 'Зараженный файл поместили в карантин.'),
    ('Вредоноссный процесс создал дочерний процесс.', 'Вредоносный процесс создал дочерний процесс.'),
    ('Событиее передали специалисту.', 'Событие передали специалисту.'),
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
    ('Восстановленние доступа одобрил администратор.', 'Восстановление доступа одобрил администратор.'),
    ('Вредоноссное вложение удалили из почты.', 'Вредоносное вложение удалили из почты.'),
    ('Проверили целостностть резервной копии.', 'Проверили целостность резервной копии.'),
    ('Пользователь ввёл неправильный паролл.', 'Пользователь ввёл неправильный пароль.'),
    ('Агент отправил отчёт с ошибкой в сводкке.', 'Агент отправил отчёт с ошибкой в сводке.'),
    ('Инженер проверил настройки приложения.', 'Инженер проверил настройки приложения.'),
    ('Документ сохранили после завершения проверки.', 'Документ сохранили после завершения проверки.'),
    ('Система обнаружила ошибку при запуске программы.', 'Система обнаружила ошибку при запуске программы.'),
    ('Оператор получил доступ через RDP и закрепился в системе.', 'Оператор получил доступ через RDP и закрепился в системе.'),
]


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
                current[j - 1] + 1,
                previous[j] + 1,
                previous[j - 1] + cost,
            ))
        previous = current
    return previous[-1]


def lcs_length(a, b):
    """Длина наибольшей общей подпоследовательности."""
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
    denominator = max(left_len, right_len)
    return distance / denominator if denominator else 0.0


def tokens(text):
    """Токенизация тем же регулярным выражением, что и у спеллчекера."""
    return WORD_RE.findall(text)


def fmt_pct(value):
    return f"{value * 100:.2f}%"


def print_section(title):
    print("\n" + "=" * 100)
    print(title)
    print("=" * 100)


def print_comparison_table(rows):
    name_width = max(52, max(len(row[0]) for row in rows) + 2)
    print(f"{'Метрика':<{name_width}} {'ДО коррекции':>18} {'ПОСЛЕ коррекции':>20}")
    print("-" * (name_width + 40))
    for name, before, after in rows:
        print(f"{name:<{name_width}} {before:>18} {after:>20}")


def evaluate_results(results, checker):
    """Считает метрики качества текста, исправлений и ранжирования."""
    sample_count = len(results)

    sum_char_distance_before = sum_char_distance_after = 0
    sum_word_distance_before = sum_word_distance_after = 0
    sum_reference_chars = sum_reference_words = 0
    sum_input_chars = sum_output_chars = 0
    sum_input_words = sum_output_words = 0
    sum_char_lcs_before = sum_char_lcs_after = 0
    sum_word_lcs_before = sum_word_lcs_after = 0
    normalized_char_before, normalized_char_after = [], []
    exact_before = exact_after = 0
    better = worse = same = 0
    aligned_samples = 0
    unaligned_samples = []
    detailed_rows = []

    # Классификация решений на уровне слов.
    typo_total = clean_total = 0
    true_positive = false_positive = false_negative = true_negative = 0
    correct_fixes = wrong_fixes = false_corrections = missed_typos = 0
    typos_not_checked = typos_without_candidates = 0

    # Ранжирование допустимых кандидатов Hunspell / ИБ-словаря.
    candidate_found = candidate_top1 = candidate_top3 = 0
    reciprocal_rank_sum = 0.0

    for sample_index, (source, expected, corrected) in enumerate(results, start=1):
        source_tokens = tokens(source)
        expected_tokens = tokens(expected)
        corrected_tokens = tokens(corrected)

        char_before = levenshtein(source, expected)
        char_after = levenshtein(corrected, expected)
        word_before = levenshtein(source_tokens, expected_tokens)
        word_after = levenshtein(corrected_tokens, expected_tokens)

        sum_char_distance_before += char_before
        sum_char_distance_after += char_after
        sum_word_distance_before += word_before
        sum_word_distance_after += word_after
        sum_reference_chars += len(expected)
        sum_reference_words += len(expected_tokens)
        sum_input_chars += len(source)
        sum_output_chars += len(corrected)
        sum_input_words += len(source_tokens)
        sum_output_words += len(corrected_tokens)

        normalized_char_before.append(
            normalized_distance(char_before, len(source), len(expected))
        )
        normalized_char_after.append(
            normalized_distance(char_after, len(corrected), len(expected))
        )

        sum_char_lcs_before += lcs_length(expected, source)
        sum_char_lcs_after += lcs_length(expected, corrected)
        sum_word_lcs_before += lcs_length(expected_tokens, source_tokens)
        sum_word_lcs_after += lcs_length(expected_tokens, corrected_tokens)

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

        if corrected != expected:
            detailed_rows.append((sample_index, source, expected, corrected))

        # Позиционное сравнение корректно, если число токенов не меняется.
        if not (len(source_tokens) == len(expected_tokens) == len(corrected_tokens)):
            unaligned_samples.append(sample_index)
            continue

        aligned_samples += 1
        for original_word, expected_word, output_word in zip(
            source_tokens, expected_tokens, corrected_tokens
        ):
            key = original_word.lower()
            status = checker.word_status.get(key)
            candidates = checker.candidate_suggestions.get(key, [])

            if original_word != expected_word:
                typo_total += 1
                if status == VALID or status is None:
                    typos_not_checked += 1
                elif not candidates:
                    typos_without_candidates += 1

                rank = next(
                    (i for i, candidate in enumerate(candidates, start=1)
                     if candidate.lower() == expected_word.lower()),
                    None,
                )
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

    cer_before = safe_div(sum_char_distance_before, sum_reference_chars)
    cer_after = safe_div(sum_char_distance_after, sum_reference_chars)
    wer_before = safe_div(sum_word_distance_before, sum_reference_words)
    wer_after = safe_div(sum_word_distance_after, sum_reference_words)

    char_precision_before = safe_div(sum_char_lcs_before, sum_input_chars)
    char_recall_before = safe_div(sum_char_lcs_before, sum_reference_chars)
    char_f1_before = safe_div(
        2 * char_precision_before * char_recall_before,
        char_precision_before + char_recall_before,
    )
    char_precision_after = safe_div(sum_char_lcs_after, sum_output_chars)
    char_recall_after = safe_div(sum_char_lcs_after, sum_reference_chars)
    char_f1_after = safe_div(
        2 * char_precision_after * char_recall_after,
        char_precision_after + char_recall_after,
    )

    token_precision_before = safe_div(sum_word_lcs_before, sum_input_words)
    token_recall_before = safe_div(sum_word_lcs_before, sum_reference_words)
    token_f1_before = safe_div(
        2 * token_precision_before * token_recall_before,
        token_precision_before + token_recall_before,
    )
    token_precision_after = safe_div(sum_word_lcs_after, sum_output_words)
    token_recall_after = safe_div(sum_word_lcs_after, sum_reference_words)
    token_f1_after = safe_div(
        2 * token_precision_after * token_recall_after,
        token_precision_after + token_recall_after,
    )

    correction_precision = safe_div(
        true_positive, true_positive + wrong_fixes + false_corrections
    )
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

    rows = [
        ("Средняя длина текста (символы)", f"{safe_div(sum_input_chars, sample_count):.2f}",
         f"{safe_div(sum_output_chars, sample_count):.2f}"),
        ("Средняя длина текста (токены)", f"{safe_div(sum_input_words, sample_count):.2f}",
         f"{safe_div(sum_output_words, sample_count):.2f}"),
        ("Среднее расстояние Левенштейна (символы)",
         f"{safe_div(sum_char_distance_before, sample_count):.3f}",
         f"{safe_div(sum_char_distance_after, sample_count):.3f}"),
        ("Среднее расстояние Левенштейна (токены)",
         f"{safe_div(sum_word_distance_before, sample_count):.3f}",
         f"{safe_div(sum_word_distance_after, sample_count):.3f}"),
        ("Нормированное расстояние (символы, среднее)",
         f"{safe_div(sum(normalized_char_before), sample_count):.5f}",
         f"{safe_div(sum(normalized_char_after), sample_count):.5f}"),
        ("Сходство символов (1 - норм. расстояние)",
         f"{1 - safe_div(sum(normalized_char_before), sample_count):.5f}",
         f"{1 - safe_div(sum(normalized_char_after), sample_count):.5f}"),
        ("CER общий (сумма Lev / сумма символов эталона)",
         f"{cer_before:.5f}", f"{cer_after:.5f}"),
        ("WER общий (сумма Lev / сумма токенов эталона)",
         f"{wer_before:.5f}", f"{wer_after:.5f}"),
        ("Char precision (по LCS)", fmt_pct(char_precision_before), fmt_pct(char_precision_after)),
        ("Char recall (по LCS)", fmt_pct(char_recall_before), fmt_pct(char_recall_after)),
        ("Char F1 (по LCS)", fmt_pct(char_f1_before), fmt_pct(char_f1_after)),
        ("Token precision (по LCS)", fmt_pct(token_precision_before), fmt_pct(token_precision_after)),
        ("Token recall (по LCS)", fmt_pct(token_recall_before), fmt_pct(token_recall_after)),
        ("Token F1 (по LCS)", fmt_pct(token_f1_before), fmt_pct(token_f1_after)),
        ("Точные совпадения предложений", f"{exact_before}/{sample_count}",
         f"{exact_after}/{sample_count}"),
        ("Баланс длины (символы эталона минус текст)",
         f"{sum_reference_chars - sum_input_chars}",
         f"{sum_reference_chars - sum_output_chars}"),
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
    print(f"Проверено предложений с одинаковым числом токенов: {aligned_samples}/{sample_count}")
    if unaligned_samples:
        print(f"Пропущены для позиционных метрик: {unaligned_samples}")
    print(f"Реальных опечаток в эталонной разметке:           {typo_total}")
    print(f"Правильно исправлено:                            {correct_fixes}")
    print(f"Исправлено неправильным вариантом:                {wrong_fixes}")
    print(f"Опечаток оставлено без изменения:                 {missed_typos}")
    print(f"Опечаток, которые система посчитала правильными: {typos_not_checked}")
    print(f"Опечаток без допустимых кандидатов:                {typos_without_candidates}")
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
    print(f"MRR (от всех опечаток):                            {candidate_mrr:.4f}")

    if detailed_rows:
        print_section("ТЕКСТЫ С РАСХОЖДЕНИЯМИ С ЭТАЛОНОМ")
        for sample_index, source, expected, corrected in detailed_rows:
            print(f"\n[{sample_index}] ИСХОДНЫЙ:  {source}")
            print(f"    ЭТАЛОН:    {expected}")
            print(f"    РЕЗУЛЬТАТ:  {corrected}")

    return {
        "typos": typo_total,
        "correct_fixes": correct_fixes,
        "false_corrections": false_corrections,
        "precision": correction_precision,
        "recall": correction_recall,
        "f1": correction_f1,
        "cer_before": cer_before,
        "cer_after": cer_after,
        "wer_before": wer_before,
        "wer_after": wer_after,
    }


def main():
    start_init = time.perf_counter()
    checker = SpellChecker(learning_enabled=False)
    init_time = time.perf_counter() - start_init

    results = []
    checker_time = 0.0
    start_total = time.perf_counter()
    for source, expected in SAMPLES:
        corrected, elapsed = checker.check(source)
        checker_time += elapsed
        results.append((source, expected, corrected))
    wall_time = time.perf_counter() - start_total

    metrics = evaluate_results(results, checker)

    total_tokens = sum(len(tokens(source)) for source, _ in SAMPLES)
    print_section("ПРОИЗВОДИТЕЛЬНОСТЬ")
    print(f"Время инициализации:                    {init_time:.2f} сек.")
    print(f"Время проверки всего набора:            {checker_time:.2f} сек.")
    print(f"Полное время цикла тестирования:        {wall_time:.2f} сек.")
    print(f"Среднее время обработки предложения:    {safe_div(checker_time, len(SAMPLES)):.3f} сек.")
    print(f"Среднее время обработки одного токена:  {safe_div(checker_time, total_tokens) * 1000:.2f} мс.")
    print(f"Всего предложений:                      {len(SAMPLES)}")
    print(f"Всего токенов в исходных текстах:       {total_tokens}")
    print(f"Вызовов Hunspell:                       {checker.hunspell_calls}")
    print(f"Время внутри Hunspell:                  {checker.hunspell_calls_time:.2f} сек.")

    print_section("КРАТКИЙ ИТОГ")
    print(f"CER:       {metrics['cer_before']:.5f} -> {metrics['cer_after']:.5f}")
    print(f"WER:       {metrics['wer_before']:.5f} -> {metrics['wer_after']:.5f}")
    print(f"Precision: {fmt_pct(metrics['precision'])}")
    print(f"Recall:    {fmt_pct(metrics['recall'])}")
    print(f"F1:        {fmt_pct(metrics['f1'])}")
    print(f"Правильно исправлено опечаток: {metrics['correct_fixes']}/{metrics['typos']}")
    print(f"Ложных исправлений правильных слов: {metrics['false_corrections']}")

    checker.close()


if __name__ == "__main__":
    main()
