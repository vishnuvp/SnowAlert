"""Basic Baseline

Compare the count of events in a window to percentiles of counts in prior windows.
"""

OPTIONS = [
    {'name': 'window_size'},
    {'name': 'history_size'},
    {'name': 'drop_zeros', 'type': 'bool'},
]


def create():
    pass
