import os
import re

def main():
    source = "data.txt"
    if not os.path.exists(source):
        print(f"Ошибка: Создай файл {source} с текстом!")
        return

    with open(source, "r", encoding="utf-8") as f:
        content = f.read()

    # Делим текст по '1111', игнорируя любые пробелы и переносы строк вокруг него
    blocks = re.split(r'\s*1111\s*', content)

    # Ищем первый свободный номер (начнет с 004, если 001-003 есть)
    counter = 1
    while os.path.exists(f"advisory_{counter:03d}.txt"):
        counter += 1

    # Создаем много файлов
    created_count = 0
    for block in blocks:
        text = block.strip()
        if text:  # Пропускаем пустые куски
            filename = f"advisory_{counter:03d}.txt"
            with open(filename, "w", encoding="utf-8") as out:
                out.write(text)
            print(f"Создан: {filename}")
            counter += 1
            created_count += 1

    print(f"\nВсего создано файлов: {created_count}")

if __name__ == "__main__":
    main()
