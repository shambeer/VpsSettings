import contextlib
import hashlib
import json
import os
import re
from pathlib import Path
import sys
import time

from vps_migration.core import common as c

ACTIVE = None


def code_digest():
    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    for path in sorted(root.rglob('*.py')):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


class Session:
    def __init__(self, path=None):
        self.path = Path(path).resolve() if path else None
        self.cursor = 0
        self.lock = None
        self.state = {'format': 1, 'code': code_digest(), 'prompts': [], 'steps': {}, 'done': False}
        if self.path:
            if self.path.stat().st_size > 4 * 1024 ** 2:
                raise ValueError('Журнал операции слишком большой')
            self.state = json.loads(self.path.read_text(encoding='utf-8'))
            if self.state.get('format') != 1 or self.state.get('code') != code_digest():
                raise RuntimeError('Продолжение требует исходную версию мигратора. Используйте resume_command из session.json')
            if Path(self.state['output']).resolve() != self.path.parent:
                raise RuntimeError('Папка журнала не совпадает с папкой операции')
            if self.state.get('done'):
                raise RuntimeError('Эта операция уже завершена; повторный запуск не нужен')

    def save(self):
        if self.path:
            for attempt in range(8):
                try:
                    c.write(self.path, self.state)
                    return
                except PermissionError:
                    if attempt == 7:
                        raise
                    time.sleep(0.1)

    def acquire(self):
        if self.lock:
            return
        self.lock = (self.path.parent / 'session.lock').open('a+b')
        try:
            if self.lock.seek(0, 2) == 0:
                self.lock.write(b'0')
                self.lock.flush()
            self.lock.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self.lock.close()
            self.lock = None
            raise RuntimeError('Этот журнал уже открыт другим процессом мигратора') from error
        if self.path.exists():
            current = json.loads(self.path.read_text(encoding='utf-8'))
            if current.get('done') or current.get('code') != code_digest():
                self.close()
                raise RuntimeError('Журнал уже завершён или относится к другой версии')
            self.state = current

    def close(self):
        if self.lock:
            self.lock.close()
            self.lock = None

    def attach(self, output):
        if not self.path:
            self.path = output / 'session.json'
            self.state['output'] = str(output.resolve())
            self.acquire()
            self.state['resume_command'] = self.recovery_command()
            self.save()
        return self.path.parent

    def prompt(self, prompt, default, read):
        if self.cursor < len(self.state['prompts']):
            row = self.state['prompts'][self.cursor]
            if row['prompt'] != prompt or row['default'] != default:
                raise RuntimeError('Порядок вопросов изменился; автоматическое продолжение остановлено')
            value = row['value']
        else:
            value = read(prompt, default)
            confirmation = re.search(r'\b(?:BACKUP|DEPLOY|RELAY|PLAN|UPGRADE|DELETE|REBOOT) (?:\d{1,3}\.){3}\d{1,3}', prompt)
            if confirmation and value != confirmation.group():
                return value
            self.state['prompts'].append({'prompt': prompt, 'default': default, 'value': value})
        self.cursor += 1
        self.save()
        return value

    def step(self, key, execute):
        row = self.state['steps'].get(key)
        if row and row.get('done'):
            if row['start'] != self.cursor:
                raise RuntimeError('Нарушен порядок контрольных точек операции: ' + key)
            self.cursor = row['end']
            return row.get('value')
        start = self.cursor
        value = execute()
        self.state['steps'][key] = {'done': True, 'start': start, 'end': self.cursor, 'value': value}
        self.save()
        return value

    def recovery_command(self):
        import shlex
        arguments = [sys.executable, '-X', 'utf8', str(Path(__file__).resolve().parents[2] / 'migrate.py'),
                     '--resume', str(self.path)]
        if os.name == 'nt':
            return '& ' + ' '.join("'" + value.replace("'", "''") + "'" for value in arguments)
        return shlex.join(arguments)


@contextlib.contextmanager
def active(session):
    global ACTIVE
    previous = ACTIVE
    ACTIVE = session
    try:
        if session.path:
            session.acquire()
        yield
    finally:
        session.close()
        ACTIVE = previous


def checkpoint(key, execute):
    if ACTIVE:
        return ACTIVE.step(key, execute)
    return execute()
