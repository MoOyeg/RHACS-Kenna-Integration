import httpx


async def get_acs_alert(url,alert_id: str) -> dict:
    """Get ACS alert from the API"""
    rhacs_alert_url_path="/v1/alerts/{alert_id}"
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{rhacs_alert_url_path.format(alert_id=alert_id)}"
        )
        return response.json()
