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


@register.filter
def typeof(value):
    return type(value).__name__

@register.filter()
def to_float(value):
    return float(value)
    
@register.filter
def range_filter(value):
    return range(1, value + 1)

@register.filter
def get_item(queryset, index):
    try:
        return queryset[int(index) - 1]  # Adjust index based on zero-based indexing
    except (IndexError, ValueError):
        return None
    
@register.filter
def to(value, end):
    return range(value, end+1)

@register.filter
def sub(value, arg):
    try:
        return value - arg
    except (TypeError, ValueError):
        return value

@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)

@register.filter(name='dict_key')
def dict_key(dictionary, key):
    return dictionary.get(key)

@register.filter
def total_amount(emi_data):
    """Sums total_amount from a list of dictionaries."""
    return float(sum(emi['total_amount'] for emi in emi_data))


@register.filter
def subtract(value, amount):
    """Subtracts amount from value."""
    return float(value) - float(amount)

@register.filter
def range_filter(value):
    return range(value)

@register.filter
def order_by(queryset, args):
    args = [x.strip() for x in args.split(',')]
    return queryset.sort(*args)

@register.filter
def format_date(value):
    """Formats a date as dd-mm-yyyy. Converts string to date if necessary."""
    if isinstance(value, str):
        # Try to parse the string as a date
        try:
            # Adjust the format as necessary (assumes 'YYYY-mm-dd')
            value = datetime.datetime.strptime(value, '%Y-%m-%d')
        except ValueError:
            return value  # Return the original string if parsing fails
    
    if isinstance(value, datetime.datetime):
        return value.strftime('%d-%m-%Y')  # Format the date

    return ''  # Return empty string if value is None or not a date

@register.filter
def last_class_status(payment):
    for option in [
        payment.single_payment,
        payment.emi_1_payments,
        payment.emi_2_payments,
        payment.emi_3_payments,
        payment.emi_4_payments,
        payment.emi_5_payments,
        payment.emi_6_payments,
    ]:
        if option:
            return option[-1].class_status
    return "N/A"