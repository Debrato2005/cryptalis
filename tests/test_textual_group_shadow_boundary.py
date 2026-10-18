"""GROUP BY input-name precedence remains protected despite a public alias."""
import pytest
from sqlalchemy import func, select

from test_textual_from_boundary import _exercise


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_group_name_shadow_resolves_protected_input_and_requires_refusal(protected, mode):
    def queries(app):
        model = app.Customer
        # PostgreSQL resolves the grouping name to the input column, although
        # the selected public aggregate has that output label. Native execution
        # is the oracle; grouping by the output aggregate would be invalid.
        base = select(func.count().label("name")).select_from(model).where(
            model.tenant_id == app.tenant)
        return base.group_by("name"), base.group_by(model.name)

    _exercise(protected, mode, queries, refuse=protected, grouped=True)
