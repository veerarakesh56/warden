"""Fixtures several test files share, offered to every test by tests/conftest.py (`pytest_plugins`).

Each stays defined in the file it belongs to; a file that needs one of another file's fixtures asks for it by
name and no longer imports it, so no import has to be hidden from the linter (F401/F811 suppressions). A file's
own fixture of the same name still wins inside that file.
"""

from test_approval_ladder_h10 import sink
from test_approval_page import setup as page_setup
from test_aws_platform_g6 import aws
from test_discuss_g10v import world as discuss_world
from test_lambdas_g6 import submitted
from test_passkey_workflow_h6 import phone
from test_remediation_workflow import owner, world

__all__ = ["aws", "discuss_world", "owner", "page_setup", "phone", "sink", "submitted", "world"]
