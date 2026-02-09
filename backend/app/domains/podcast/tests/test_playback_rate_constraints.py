from app.domains.podcast.models import PodcastPlaybackState
from app.domains.subscription.models import UserSubscription
from app.domains.user.models import User


def _constraint_sql_text(table, constraint_name: str) -> str | None:
    for constraint in table.constraints:
        if getattr(constraint, "name", None) == constraint_name:
            return str(getattr(constraint, "sqltext", ""))
    return None


def test_podcast_playback_rate_column_and_constraint():
    column = PodcastPlaybackState.__table__.c.playback_rate
    sql_text = _constraint_sql_text(
        PodcastPlaybackState.__table__,
        "ck_podcast_playback_states_playback_rate_range",
    )

    assert column.nullable is False
    assert sql_text is not None
    assert "playback_rate >= 0.5" in sql_text
    assert "playback_rate <= 3.0" in sql_text


def test_user_default_playback_rate_column_and_constraint():
    column = User.__table__.c.default_playback_rate
    sql_text = _constraint_sql_text(
        User.__table__,
        "ck_users_default_playback_rate_range",
    )

    assert column.nullable is False
    assert sql_text is not None
    assert "default_playback_rate >= 0.5" in sql_text
    assert "default_playback_rate <= 3.0" in sql_text


def test_subscription_playback_preference_column_and_constraint():
    column = UserSubscription.__table__.c.playback_rate_preference
    sql_text = _constraint_sql_text(
        UserSubscription.__table__,
        "ck_user_subscriptions_playback_rate_preference_range",
    )

    assert column.nullable is True
    assert sql_text is not None
    assert "playback_rate_preference >= 0.5" in sql_text
    assert "playback_rate_preference <= 3.0" in sql_text
