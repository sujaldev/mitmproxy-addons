"""
Intercepts requests to websites whose domain names seem like a typo for a popular website, and replaces it with a page
asking "Did you mean xyz?".

Example: gamil.com will be replaced with a page asking "Did you mean gmail.com?"
"""
from io import StringIO
from pathlib import Path
from string import Template

from mitmproxy import http
from symspellpy import SymSpell, Verbosity


def remove_dots(string: str) -> str:
    return "".join(string.split("."))


class SpellCheck:
    POPULAR_DOMAINS = [
        "google.com", "gmail.com", "youtube.com", "github.com", "stackoverflow.com", "stackexchange.com", "reddit.com",
        "lobste.rs", "news.ycombinator.com"
    ]

    def __init__(self):
        self.sym_spell = SymSpell()

        # removing the dot separators from domain names because otherwise the spell check library will provide
        # suggestions like reddit.rs
        self.dict = {
            remove_dots(name): name for name in self.POPULAR_DOMAINS
        }
        self.sym_spell.create_dictionary(StringIO(
            "\n".join(self.dict.keys())
        ))

        with open(Path(__file__).parent / "template.html") as file:
            self.html = Template(file.read())

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
        if flow.request.host == "mitm.it":
            self.process_state_update_request(flow)
        else:
            self.process_other_requests(flow)

    def process_state_update_request(self, flow: http.HTTPFlow) -> None:
        if blacklist_domain := flow.request.query.get("blacklist"):
            self.state[blacklist_domain] = False

        if whitelist_domain := flow.request.query.get("whitelist"):
            self.state[whitelist_domain] = True

    def process_other_requests(self, flow: http.HTTPFlow) -> None:
        whitelisted = self.state.get(flow.request.host)

        if whitelisted:
            return

        corrected = self.generate_suggestion(flow.request.host)
        if not corrected:
            return

        corrected_url = f"{flow.request.scheme}://{corrected}/"

        if (whitelisted is not None) and not whitelisted:
            flow.response = http.Response.make(301, headers=(
                (b"Location", corrected_url.encode()),
            ))
            return

        flow.response = http.Response.make(200, self.html.substitute(
            original_url=flow.request.url,
            original_host=flow.request.host,
            corrected_host=corrected,
            corrected_url=corrected_url
        ))


addons = [SpellCheck()]
