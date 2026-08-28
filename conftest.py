"""Shared pytest settings for the whole test suite."""

# Imports
from hypothesis import HealthCheck, settings

# Constants
SLOW_IO_DEADLINE_MS = 2000

settings.register_profile(
    "iocs",
    deadline=SLOW_IO_DEADLINE_MS,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
settings.load_profile("iocs")
