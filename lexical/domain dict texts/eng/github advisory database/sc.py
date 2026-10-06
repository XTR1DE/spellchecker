import glob

total_words = 0
total_chars = 0
processed_files = 0

print("=== СЧИТАЮ ТОЛЬКО ADVISORY ФАЙЛЫ ===")

# Прямой захват всех файлов, начинающихся на advisory_ и заканчивающихся на .txt
for file_path in glob.glob("advisory_*.txt"):
    text = None
    # Перебор кодировок, чтобы точно прочиталось на Windows
    for encoding in ['utf-8', 'cp1251', 'latin-1']:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                text = f.read()
            break
        except UnicodeDecodeError:
            continue

    if text is not None:
        chars_count = len(text)
        words_count = len(text.split())
        
        total_chars += chars_count
        total_words += words_count
        processed_files += 1
        
        print(f"{file_path} -> Символов: {chars_count}, Слов: {words_count}")

print("-" * 40)
print(f"ИТОГ:")
print(f"Файлов сожрано: {processed_files}")
print(f"Всего символов: {total_chars}")
print(f"Всего слов: {total_words}")
a=input()