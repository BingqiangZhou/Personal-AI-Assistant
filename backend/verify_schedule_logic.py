
import sys
import os
from datetime import datetime, timedelta, timezone

# Add backend directory to sys.path
sys.path.append(os.getcwd())

from app.domains.subscription.models import Subscription, UpdateFrequency

def test_schedule_logic():
    print(f"Current UTC Time: {datetime.utcnow()}")
    
    # Test Hourly
    sub_hourly = Subscription(
        update_frequency=UpdateFrequency.HOURLY.value,
        last_fetched_at=datetime.utcnow()
    )
    next_hourly = sub_hourly.next_update_at
    print(f"Hourly Next Update: {next_hourly}")
    
    if next_hourly.minute != 0 or next_hourly.second != 0:
        print("FAIL: Hourly not aligned to hour mark")
    else:
        print("PASS: Hourly aligned")
        
    diff_hourly = next_hourly - datetime.utcnow()
    if diff_hourly > timedelta(hours=1) or diff_hourly < timedelta(seconds=0):
        print(f"FAIL: Hourly delta {diff_hourly} is out of range")
    else:
        print("PASS: Hourly delta in range")

    # Test Daily
    sub_daily = Subscription(
        update_frequency=UpdateFrequency.DAILY.value,
        last_fetched_at=datetime.utcnow()
    )
    next_daily = sub_daily.next_update_at
    print(f"Daily Next Update: {next_daily}")
    
    if next_daily.hour != 0 or next_daily.minute != 0:
        print("FAIL: Daily not aligned to midnight")
    else:
        print("PASS: Daily aligned")
        
    # Test Weekly
    sub_weekly = Subscription(
        update_frequency=UpdateFrequency.WEEKLY.value,
        last_fetched_at=datetime.utcnow()
    )
    next_weekly = sub_weekly.next_update_at
    print(f"Weekly Next Update: {next_weekly} (Weekday: {next_weekly.weekday()})")
    
    if next_weekly.weekday() != 0: # Monday is 0
        print(f"FAIL: Weekly not Monday (is {next_weekly.weekday()})")
    else:
        print("PASS: Weekly is Monday")
        
    if next_weekly.hour != 0 or next_weekly.minute != 0:
        print("FAIL: Weekly not aligned to midnight")
    else:
        print("PASS: Weekly at Midnight")

if __name__ == "__main__":
    try:
        test_schedule_logic()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
