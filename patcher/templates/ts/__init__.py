from patcher.templates.ts.innerhtml import apply as apply_innerhtml
from patcher.templates.ts.innerhtml import supports as supports_innerhtml
from patcher.templates.ts.json_eval import apply as apply_json_eval
from patcher.templates.ts.json_eval import supports as supports_json_eval
from patcher.templates.ts.regexp import apply as apply_regexp
from patcher.templates.ts.regexp import supports as supports_regexp


class Template:
    def __init__(self, supports, apply):
        self.supports = supports
        self.apply = apply


def get_ts_templates():
    return [
        Template(supports_innerhtml, apply_innerhtml),
        Template(supports_regexp, apply_regexp),
        Template(supports_json_eval, apply_json_eval),
    ]
