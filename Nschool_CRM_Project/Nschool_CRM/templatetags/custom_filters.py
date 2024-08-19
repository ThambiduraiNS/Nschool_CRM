from django import template
from django.utils.timesince import timesince
import datetime

register = template.Library()

@register.filter
def custom_timesince(value):
    now = datetime.datetime.now(datetime.timezone.utc)
    diff = now - value

    minutes = diff.total_seconds() // 60
    hours = diff.total_seconds() // 3600

    if minutes < 60:
        return f"{int(minutes)} mins ago"
    elif hours < 24:
        remaining_minutes = int(minutes % 60)
        if remaining_minutes > 0:
            return f"{int(hours)} hour{'s' if hours > 1 else ''}, {remaining_minutes} mins ago"
        else:
            return f"{int(hours)} hour{'s' if hours > 1 else ''} ago"
    else:
        # Default to Django's timesince for longer durations (like days, weeks)
        return timesince(value) + " ago"
