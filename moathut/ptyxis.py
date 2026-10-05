"""A Ptyxis profile that opens a hut the moathut way.

Ptyxis opens a container from its menu with `podman exec --privileged`,
whose bounding set is every capability. A profile whose command,
run on the host, is `moathut enter NAME` opens the hut as moathut does;
with preserve-container never, a new tab from it runs the same command,
whatever the hut has printed.

Ptyxis keeps profiles in GSettings, each at /org/gnome/Ptyxis/Profiles/
UUID/ and listed in profile-uuids. Its default is the listed profile
default-profile-uuid names, else the first listed, so a hut's profile
is added only beside a default of Ptyxis's own.
"""

import re
import shlex
import uuid

SCHEMA = "org.gnome.Ptyxis"
PROFILE_SCHEMA = "org.gnome.Ptyxis.Profile"
PROFILES = "/org/gnome/Ptyxis/Profiles/"

# A hut's profile has an id of its own, the same at every run, so the
# profile is found again without being recorded.
_NAMESPACE = uuid.UUID("6f1b5a8e-4f61-4d6b-9c43-2a1d3e7b9f05")


def profile_uuid(name):
    """Ptyxis's own ids are 32 hex digits, as this is."""
    return uuid.uuid5(_NAMESPACE, f"moathut box {name}").hex


def profile_path(name):
    return f"{PROFILES}{profile_uuid(name)}/"


def command(settings, name):
    """moathut as the hut's units run it, which works from a checkout
    too."""
    env = (["env", f"PYTHONPATH={settings.pythonpath}"]
           if settings.pythonpath else [])
    return shlex.join([*env, *settings.tool, "enter", name])


def keys(settings, name):
    """The profile's keys and their values, as GVariant text."""
    return [("label", text(f"moathut {name}")),
            ("default-container", text("session")),
            ("use-custom-command", "true"),
            ("custom-command", text(command(settings, name))),
            ("preserve-container", text("never")),
            ("preserve-directory", text("always"))]


def text(value):
    """A GVariant string."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def strings(values):
    """A GVariant array of strings."""
    return "[" + ", ".join(text(v) for v in values) + "]"


# GLib prints a string in double quotes when it holds a single one.
_STRING = re.compile(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"")


def parse_strings(printed):
    """The strings `gsettings get` printed, of an `s` or an `as`."""
    return [re.sub(r"\\(.)", r"\1",
                   m[1] if m[1] is not None else m[2])
            for m in _STRING.finditer(printed)]
