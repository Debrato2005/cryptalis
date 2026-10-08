"""New async evidence for the same three-model attachment and CF1 representation."""
import asyncio

from sqlalchemy import func, insert, inspect, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from integration_crypto import Failure
from integration_harness import Harness
from run_gate_retrofit import check


async def denied(out, name, awaitable):
    try:
        await awaitable
    except Failure:
        out[name] = "PASS"
    else:
        raise AssertionError(name)


async def exercise(h):
    from integration_async import create_guarded_async_engine
    app, out = h.app, h.outcomes
    engine = create_guarded_async_engine(h.attachment)
    try:
        async with AsyncSession(engine) as session:
            account = app.Account(name="async-parent")
            account.customers = [app.Customer(email="async@example.test", display_name="Async", age=30),
                                 app.Customer(email=None, display_name="Async null", age=None)]
            session.add(account)
            await session.flush()
            tenant, record = account.id, account.customers[0].id
            check(out, "async_generated_cascade_history", type(record) is int and not inspect(account.customers[0]).attrs.email.history.has_changes())
            await session.commit()
            customer = await session.get(app.Customer, record)
            check(out, "async_exact_scalar_type", type(customer.email) is str and customer.email == "async@example.test")
            loaded = (await session.scalars(select(app.Account).options(selectinload(app.Account.customers)).where(app.Account.id == tenant))).one()
            check(out, "async_eager_relationship", {child.display_name for child in loaded.customers} == {"Async", "Async null"})
            await session.execute(insert(app.Customer), [{"account_id": tenant, "email": "async-bulk@example.test", "display_name": "Async bulk", "age": 31}])
            await session.commit()
            check(out, "async_bulk_generated_identity", (await session.scalars(app.lookup_email(tenant, "async-bulk@example.test"))).one().display_name == "Async bulk")
            await session.execute(update(app.Customer).where(app.Customer.id == record).values(email="async-changed@example.test"))
            await session.rollback()
            await session.refresh(customer)
            check(out, "async_point_update_rollback", customer.email == "async@example.test")
            streamed = await session.stream_scalars(select(app.Customer.email).where(app.Customer.account_id == tenant).order_by(app.Customer.id))
            values = [value async for value in streamed]
            check(out, "async_server_cursor_values", values == ["async@example.test", None, "async-bulk@example.test"])
            await denied(out, "async_opaque_sql_rejected", session.execute(text("SELECT 1")))
        async with engine.connect() as connection:
            raw = await connection.get_raw_connection()
            before = h.attachment.driver_executions
            cursor = raw.driver_connection.cursor()
            await denied(out, "async_driver_execute_rejected", cursor.execute("SELECT 1"))
            try:
                cursor.copy("COPY customer FROM STDIN")
            except Failure:
                out["async_copy_rejected_before_enter"] = "PASS"
            else:
                raise AssertionError("async_copy_rejected_before_enter")
            try:
                raw.driver_connection.info.pgconn
            except Failure:
                out["async_info_protocol_handle_rejected"] = "PASS"
            else:
                raise AssertionError("async_info_protocol_handle_rejected")
            check(out, "async_raw_rejections_no_wire", before == h.attachment.driver_executions)
            await cursor.close()

        async def scoped(scope, allowed):
            with h.provider.scope(scope):
                await asyncio.sleep(0)
                async with AsyncSession(engine) as session:
                    if allowed:
                        return (await session.get(app.Customer, record)).email == "async@example.test"
                    try:
                        await session.get(app.Customer, record)
                    except Failure as failure:
                        return failure.code == "TENANT_SCOPE_DENIED"
                    return False
        check(out, "async_contextvars_isolation", all(await asyncio.gather(scoped([tenant], True), scoped([tenant + 100], False))))

        async def sleeping():
            async with AsyncSession(engine) as session:
                await session.scalar(select(func.pg_sleep(10)))
        task = asyncio.create_task(sleeping())
        await asyncio.sleep(0.15)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            out["async_driver_cancellation_observed"] = "PASS"
        else:
            raise AssertionError("async_driver_cancellation_observed")
        async with AsyncSession(engine) as session:
            check(out, "async_post_cancellation_recovery", await session.scalar(select(app.Customer.email).where(app.Customer.id == record)) == "async@example.test")
        h.result["provider_scope"] = "MEMORY_ONLY_LOCAL_PROVIDER; REAL_PROVIDER_AWAIT_CANCELLATION_UNKNOWN"
        h.result["async_bootstrap_changes"] = {"model": 0, "business_query": 0, "engine_factory": 1,
                                                "reason": "Select guarded async creator; ordinary AsyncSession remains native"}
    finally:
        await engine.dispose()


def cases(h):
    h.attach()
    asyncio.run(exercise(h))


if __name__ == "__main__":
    Harness("async").run(cases, __file__)
