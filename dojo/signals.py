from django.dispatch import Signal

dedupe_signal = Signal(providing_args=["new_finding"])
