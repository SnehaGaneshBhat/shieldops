import re

from rapidfuzz.distance import DamerauLevenshtein


DANGEROUS = re.compile(
    r"curl|wget|eval|base64|powershell|https?://",
    re.IGNORECASE,
)
HOOKS = ("preinstall", "install", "postinstall")


def clean(value, limit=300):
    value = "".join(
        char for char in str(value)
        if char.isprintable() or char == " "
    )
    return value[:limit]


def typosquat(name, top):
    name = name.lower()

    if name.startswith("@") or name in top:
        return None

    alternate = name.replace("_", "-")
    if alternate != name and alternate in top:
        return alternate, 0

    for trusted in top:
        if abs(len(trusted) - len(name)) > 2:
            continue

        distance = DamerauLevenshtein.distance(name, trusted)
        limit = 1 if len(trusted) <= 4 else 2

        if 1 <= distance <= limit:
            return trusted, distance

    return None


def install_script_hits(scripts):
    return [
        (hook, scripts[hook])
        for hook in HOOKS
        if isinstance(scripts.get(hook), str)
        and DANGEROUS.search(scripts[hook])
    ]
