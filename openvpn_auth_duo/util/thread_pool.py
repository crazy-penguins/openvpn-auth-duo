# from: https://stackoverflow.com/a/24457608/8087167

import logging
from concurrent.futures import ThreadPoolExecutor


log = logging.getLogger(__name__)


class ThreadPoolExecutorStackTraced(ThreadPoolExecutor):
    def submit(self, fn, *args, **kwargs):
        """Submits the wrapped function instead of `fn`"""

        return super().submit(self._function_wrapper, fn, *args, **kwargs)

    def _function_wrapper(self, fn, *args, **kwargs):
        """Wraps `fn` in order to preserve the traceback of any kind of
        raised exception

        """
        try:
            return fn(*args, **kwargs)
        except Exception as ex:
            log.exception('Exception in thread: %s', ex)
