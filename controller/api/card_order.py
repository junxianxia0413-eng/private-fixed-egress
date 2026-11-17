import json

from fastapi import APIRouter, HTTPException, Request

from controller.api.gateways import authenticated_form
from controller.services.database import audit, connect

router = APIRouter()
TABLES = {"exits": "exit_groups", "devices": "devices", "groups": "subscription_groups"}


@router.post("/api/cards/{page}/order")
async def reorder(request: Request, page: str):
    session, form = await authenticated_form(request)
    table = TABLES.get(page)
    if not table:
        raise HTTPException(404, "找不到卡片列表。")
    try:
        order = json.loads(form.get("order", ""))
        if not isinstance(order, list) or any(type(item) is not int for item in order):
            raise ValueError
    except ValueError:
        raise HTTPException(400, "排序无效。") from None
    settings = request.app.state.settings
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        current = {row[0] for row in db.execute(f"SELECT id FROM {table}")}
        if len(order) != len(current) or set(order) != current:
            raise HTTPException(409, "卡片列表已变化，请刷新后重试。")
        db.executemany(
            f"UPDATE {table} SET display_order=? WHERE id=?",
            [(position, identifier) for position, identifier in enumerate(order, 1)],
        )
        audit(db, session["username"], f"{page}.reordered")
    return {"ok": True}
