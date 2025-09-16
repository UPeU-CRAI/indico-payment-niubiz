class DockerException(Exception):
    pass


class DockerClient:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def close(self):  # pragma: no cover - stub
        return None


Client = DockerClient
from_env = lambda *args, **kwargs: DockerClient(*args, **kwargs)

from . import errors  # noqa: E402  # re-export for compatibility

__all__ = ('Client', 'DockerClient', 'DockerException', 'from_env', 'errors')
