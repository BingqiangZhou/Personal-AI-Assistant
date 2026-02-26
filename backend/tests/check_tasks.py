"""Quick script to verify task registration."""

from app.core.celery_app import celery_app


def main():
    print("Registered tasks:")
    for name in sorted(celery_app.tasks.keys()):
        if name.startswith("app.domains.podcast.tasks"):
            print(f"  - {name}")

    # Check expected tasks
    expected = {
        "app.domains.podcast.tasks.transcription.process_audio_transcription",
        "app.domains.podcast.tasks.transcription.process_podcast_episode_with_transcription",
        "app.domains.podcast.tasks.summary_generation.generate_pending_summaries",
        "app.domains.podcast.tasks.summary_generation.generate_summary_for_episode",
    }

    registered = set(celery_app.tasks.keys())
    missing = expected - registered

    if missing:
        print(f"\nMissing tasks: {missing}")
        return False
    else:
        print("\nAll expected tasks are registered!")
        return True

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
