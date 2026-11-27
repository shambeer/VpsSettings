import contextlib
from pathlib import Path

from vps_migration.core import common as c

BASE = Path('/root/vps-transfer')
TASKS = {'backup', 'deploy', 'relay', 'maintenance-apply'}


class AlreadyStarted(RuntimeError):
    pass


@contextlib.contextmanager
def claim(job, action):
    import fcntl
    if job.parent != BASE or not job.is_dir():
        raise ValueError('Недопустимый каталог серверной задачи')
    with (job / (action + '-execution.lock')).open('a') as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AlreadyStarted('Задача уже выполняется; подключитесь к наблюдению') from error
        path = job / (action + '-execution.json')
        if path.exists():
            raise AlreadyStarted('Задача уже запускалась; повторное выполнение запрещено')
        state = {'action': action, 'phase': 'running',
                 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
        c.write(path, state)
        try:
            yield
        except BaseException:
            c.write(path, {**state, 'phase': 'failed'})
            raise
        else:
            c.write(path, {**state, 'phase': 'finished'})
