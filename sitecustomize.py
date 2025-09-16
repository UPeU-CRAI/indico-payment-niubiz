import os
import sys
import types

os.environ.setdefault('PYTEST_DISABLE_PLUGIN_AUTOLOAD', '1')

repo_root = os.path.dirname(__file__)
if repo_root and repo_root not in sys.path:
    sys.path.insert(0, repo_root)

if 'docker' not in sys.modules:
    docker_module = types.ModuleType('docker')

    class _DockerClientStub:  # pragma: no cover - simple stub for tests
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

        def close(self):  # pragma: no cover - defensive
            return None

    docker_module.Client = _DockerClientStub
    docker_module.DockerClient = _DockerClientStub
    docker_module.from_env = lambda *args, **kwargs: _DockerClientStub(*args, **kwargs)
    docker_module.errors = types.SimpleNamespace(DockerException=Exception)
    sys.modules['docker'] = docker_module
