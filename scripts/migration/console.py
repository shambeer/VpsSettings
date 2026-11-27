import textwrap

WIDTH = 76


def section(title):
    print('\n╭' + '─' * WIDTH + '╮', flush=True)
    for line in textwrap.wrap(title, WIDTH - 4, break_long_words=False) or ['']:
        print('│  ' + line.ljust(WIDTH - 4) + '  │', flush=True)
    print('╰' + '─' * WIDTH + '╯', flush=True)


def menu(title, options):
    section(title)
    for number, label in options:
        lines = textwrap.wrap(label, WIDTH - 8, break_long_words=False) or ['']
        print('  ' + str(number) + '. ' + lines[0], flush=True)
        for line in lines[1:]:
            print('     ' + line, flush=True)
    print('', flush=True)


def prompt(question, default=None):
    print('\n  [ОЖИДАНИЕ ВВОДА]', flush=True)
    for line in textwrap.wrap(question, WIDTH - 4, break_long_words=False):
        print('  ' + line, flush=True)
    if default is None:
        print('  Введите значение и нажмите Enter. Поле обязательно.', flush=True)
    elif default == '':
        print('  Введите значение и нажмите Enter. Чтобы пропустить, нажмите Enter.', flush=True)
    else:
        print('  Enter без ввода: ' + str(default), flush=True)
    while True:
        value = input('  > ').strip()
        if value:
            return value
        if default is not None:
            return default
        print('  Значение не введено. Введите его после > и нажмите Enter.', flush=True)


def error(message):
    print('\n  Ошибка: ' + str(message) + '\n  Попробуйте ещё раз.', flush=True)


def select(question, allowed, default=None, read=None):
    read = read or prompt
    while True:
        value = read(question, default)
        if value in allowed:
            return value
        error('Выберите один из вариантов: ' + ', '.join(allowed))
