import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest

import indico_payment_niubiz.client as client_module  # noqa: E402
import indico_payment_niubiz.controllers as controllers  # noqa: E402

controllers._ = lambda text: text  # type: ignore
client_module._ = lambda text: text  # type: ignore


@pytest.fixture(autouse=True)
def _reset_token_cache():
    client_module.clear_token_cache()
    yield
    client_module.clear_token_cache()
