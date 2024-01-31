"""
Intercepts requests to websites whose domain names seem like a typo for a popular website, and replaces it with a page
asking "Did you mean xyz?".

Example: gamil.com will be replaced with a page asking "Did you mean gmail.com?"
"""
from io import StringIO

from mitmproxy import http
from symspellpy import SymSpell, Verbosity


def remove_dots(string: str) -> str:
    return "".join(string.split("."))


class SpellCheck:
    POPULAR_DOMAINS = ["google.com"]

    def __init__(self):
        self.sym_spell = SymSpell()

        self.dict = {
            remove_dots(name): name for name in self.POPULAR_DOMAINS
        }
        self.sym_spell.create_dictionary(StringIO(
            "\n".join(self.dict.keys())
        ))

        # TODO: persist state
        self.state = {}

    def generate_suggestion(self, host) -> str | None:
        host = remove_dots(host)
        suggestions = self.sym_spell.lookup(host, Verbosity.CLOSEST)

        if not suggestions:
            return

        least_edit_distance, final_suggestion = suggestions[0].distance, suggestions[0].term
        for current_suggestion in suggestions[1:]:
            if current_suggestion.distance < least_edit_distance or final_suggestion == host:
                final_suggestion = current_suggestion.term

        if final_suggestion != host:
            return self.dict[final_suggestion]

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        if flow.request.host != "mitm.it":
            return

        if blacklist_domain := flow.request.query.get("blacklist"):
            self.state[blacklist_domain] = False

        if whitelist_domain := flow.request.query.get("whitelist"):
            self.state[whitelist_domain] = True

    def request(self, flow: http.HTTPFlow) -> None:
        pass


addons = [SpellCheck()]
