"""Export workflows for subscriptions."""

from __future__ import annotations

from datetime import datetime, timezone
from xml.etree.ElementTree import Element, SubElement, tostring

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.domains.subscription.models import Subscription, SubscriptionStatus, UserSubscription

from .common import SubscriptionServiceSupport


class SubscriptionExportService:
    """Generate subscription exports such as OPML."""

    def __init__(self, support: SubscriptionServiceSupport):
        self.support = support
        self.db = support.db

    async def generate_opml_content(
        self,
        user_id: int | None = None,
        status_filter: str | None = SubscriptionStatus.ACTIVE,
    ) -> str:
        opml = Element("opml", version="2.0")
        head = SubElement(opml, "head")
        SubElement(head, "title").text = "Stella RSS Subscriptions"
        SubElement(head, "dateCreated").text = datetime.now(timezone.utc).strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        SubElement(head, "ownerName").text = "Stella Admin"

        if user_id is not None:
            query = (
                select(Subscription)
                .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
                .options(selectinload(Subscription.categories))
                .where(UserSubscription.user_id == user_id, not UserSubscription.is_archived)
            )
        else:
            query = select(Subscription).options(selectinload(Subscription.categories))

        if status_filter:
            query = query.where(Subscription.status == status_filter)

        query = query.order_by(Subscription.title)
        result = await self.db.execute(query)
        subscriptions = result.scalars().all()
        SubElement(head, "totalSubscriptions").text = str(len(subscriptions))

        body = SubElement(opml, "body")
        categorized_subs: dict[str, list[Subscription]] = {}
        uncategorized_subs: list[Subscription] = []

        for sub in subscriptions:
            if sub.categories:
                category_name = sub.categories[0].name
                categorized_subs.setdefault(category_name, []).append(sub)
            else:
                uncategorized_subs.append(sub)

        for category_name in sorted(categorized_subs.keys()):
            category_outline = SubElement(body, "outline")
            category_outline.set("text", category_name)
            category_outline.set("title", category_name)
            for sub in categorized_subs[category_name]:
                self.support.add_subscription_to_opml(category_outline, sub)

        for sub in uncategorized_subs:
            self.support.add_subscription_to_opml(body, sub)

        return tostring(opml, encoding="unicode", xml_declaration=True)