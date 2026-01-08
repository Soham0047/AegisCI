from patcher.templates.python.compare_digest import apply as apply_compare_digest
from patcher.templates.python.compare_digest import supports as supports_compare_digest
from patcher.templates.python.secrets_token import apply as apply_secrets_token
from patcher.templates.python.secrets_token import supports as supports_secrets_token
from patcher.templates.python.subprocess_shell import apply as apply_subprocess_shell
from patcher.templates.python.subprocess_shell import supports as supports_subprocess_shell


class Template:
    def __init__(self, supports, apply):
        self.supports = supports
        self.apply = apply


def get_python_templates():
    return [
        Template(supports_subprocess_shell, apply_subprocess_shell),
        Template(supports_compare_digest, apply_compare_digest),
        Template(supports_secrets_token, apply_secrets_token),
    ]
