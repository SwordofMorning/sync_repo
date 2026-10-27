import re
from typing import Dict, Tuple

class SanitizerError(Exception):
    pass

class MetadataSanitizer:
    def __init__(self, identity_map: Dict[str, str], message_rules: list):
        self.identity_map = identity_map
        self.message_rules = []
        for r in message_rules:
            try:
                self.message_rules.append({
                    "regex": re.compile(r["pattern"]),
                    "replacement": r["replacement"]
                })
            except re.error as e:
                pass

    def sanitize_identity(self, name: str, email: str) -> Tuple[str, str]:
        key = f"{name} <{email}>"
        if key in self.identity_map:
            mapped = self.identity_map[key]
            # parse mapped "Name <email>"
            m = re.match(r"^([^<]+)<([^>]+)>$", mapped.strip())
            if m:
                return m.group(1).strip(), m.group(2).strip()
            return mapped, email

        # Fail closed on unknown authors to prevent leaking private emails
        raise SanitizerError(
            f"Unknown author/committer identity '{key}' not registered in identity_map. "
            f"Failing closed to prevent metadata leak."
        )

    def sanitize_message(self, raw_message: str) -> str:
        msg = raw_message

        # 1. Clean cherry-pick references
        msg = re.sub(r"\(cherry picked from commit [a-f0-9]{40}\)", "", msg)

        # 2. Apply configured sanitization rules (using \g<1> for group references)
        for r in self.message_rules:
            regex = r["regex"]
            repl = r["replacement"]
            msg = regex.sub(repl, msg)

        # 3. Clean specific internal merge patterns
        msg = re.sub(r"Merge remote-tracking branch 'origin/main' into [a-zA-Z0-9_-]+", "Merge branch 'main'", msg)
        msg = re.sub(r"Merge [a-f0-9]{8,40} \(origin/([a-zA-Z0-9_-]+)\)", r"Merge branch '\g<1>'", msg)
        msg = re.sub(r"origin/([a-zA-Z0-9_-]+)", r"\g<1>", msg)

        # 4. Strip extraneous blank lines
        lines = [l.rstrip() for l in msg.splitlines()]
        cleaned = "\n".join(lines).strip() + "\n"
        return cleaned

    def build_commit_env(self, meta: dict) -> Tuple[dict, str]:
        author_name, author_email = self.sanitize_identity(meta["author_name"], meta["author_email"])
        committer_name, committer_email = self.sanitize_identity(meta["committer_name"], meta["committer_email"])
        sanitized_msg = self.sanitize_message(meta["message"])

        env = {
            "GIT_AUTHOR_NAME": author_name,
            "GIT_AUTHOR_EMAIL": author_email,
            "GIT_AUTHOR_DATE": meta["author_date"],
            "GIT_COMMITTER_NAME": committer_name,
            "GIT_COMMITTER_EMAIL": committer_email,
            "GIT_COMMITTER_DATE": meta["committer_date"]
        }
        return env, sanitized_msg
