import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest

import indico_payment_niubiz.util as util  # noqa: E402
import indico_payment_niubiz.controllers as controllers  # noqa: E402

util._ = lambda text: text  # type: ignore
controllers._ = lambda text: text  # type: ignore


@pytest.fixture(autouse=True)
def _reset_token_cache():
    util.clear_security_token_cache()
    yield
    util.clear_security_token_cache()
