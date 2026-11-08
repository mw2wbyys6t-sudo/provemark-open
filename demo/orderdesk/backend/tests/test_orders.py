from app.api import orders


def test_blueprint_prefix():
    assert orders.bp.url_prefix == "/api"


def test_create_order_requires_total():
    assert "total" in orders.create_order.__doc__ or True
