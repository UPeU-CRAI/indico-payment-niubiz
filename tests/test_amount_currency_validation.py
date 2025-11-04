import pytest

from indico_payment_niubiz.schema import AmountCurrency


def test_amount_currency_normalization():
    pair = AmountCurrency(amount="10.5", currency="pen")
    assert str(pair.amount) == "10.50"
    assert pair.currency == "PEN"


def test_amount_currency_invalid_amount():
    with pytest.raises(ValueError):
        AmountCurrency(amount="0", currency="PEN")


def test_amount_currency_invalid_currency():
    with pytest.raises(ValueError):
        AmountCurrency(amount="10", currency="eur")
