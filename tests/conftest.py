import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ciscogen.generators import generate_config  # noqa: E402
from ciscogen.models import Project              # noqa: E402
from ciscogen.profiles import load_profiles      # noqa: E402


@pytest.fixture(scope="session")
def profiles():
    return load_profiles()


@pytest.fixture
def project():
    """Fresh project on a Catalyst 9300 with only system+interfaces enabled."""
    p = Project()
    p.device_model = "Catalyst 9300"
    p.os_type = "IOS-XE"
    p.os_version = "17.9"
    return p


def gen(project, profiles):
    return generate_config(project, profiles[project.device_model])
