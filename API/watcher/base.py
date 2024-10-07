from abc import abstractmethod

from utils.utils import run_thread


class AbstractWatcher:
    def __init__(self, interval=500, pending_interval=30):
        run_thread(target=self.run, name='abstract_watcher', args=(interval, pending_interval))

    @abstractmethod
    def run(self, interval, pending_interval):
        raise NotImplementedError('Watcher must have run method and accept interval param')
