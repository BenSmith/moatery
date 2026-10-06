#!/usr/bin/env python3
"""moathut's seccomp profiles: what each refuses, with which errno, by
evaluating the rules as the kernel's filter would; and the shapes
libseccomp misreads.

Measured on the proving host (2026-10-04; podman 5.8.7, crun 1.28,
libseccomp 2.6.1, kernel 7.2.5), each call made with an argument the
kernel itself rejects, so the errno tells which refused it:

- A rule naming one argument twice (family > 16 and != 40) let every
  family through, vsock with it.
- Of two overlapping rules, the one with fewer conditions won, whatever
  their order: an allow of family != 40 overruled a refusal of the audit
  socket.
- A refusal of socket's family beside two allows of it (EQ, MASKED_EQ
  or LT) failed to load: "seccomp_rule_add_array: File exists".
- podman's default refuses a vsock by comparing the whole register,
  which the kernel reads as an int: socket((1 << 32) | AF_VSOCK, ...)
  returned a vsock under it. Under `strict` it fails with ENOSYS.
"""

import json
import unittest

from moathut import seccomp
from moathut.seccomp import (AF_NETLINK, AF_VSOCK, CLONE_NEW, CLONE_NEWTIME,
                             DEBUG, EINVAL, ENOSYS, EPERM, NETLINK_AUDIT,
                             profile)
from moathut.units import CAPABILITIES

ALLOW = "allow"
MASK64 = (1 << 64) - 1
CLONE_THREAD = 0x10000
SIGCHLD = 17


def _holds(cmp, args):
    value = args[cmp["index"]] & MASK64
    op = cmp["op"].removeprefix("SCMP_CMP_")
    if op == "MASKED_EQ":
        return value & cmp["value"] == cmp["valueTwo"]
    return {"EQ": value == cmp["value"], "NE": value != cmp["value"],
            "LT": value < cmp["value"], "LE": value <= cmp["value"],
            "GT": value > cmp["value"], "GE": value >= cmp["value"]}[op]


def _applies(entry, arch):
    includes = entry.get("includes", {}).get("arches")
    excludes = entry.get("excludes", {}).get("arches", ())
    return (includes is None or arch in includes) and arch not in excludes


def _verdict(entry):
    if entry["action"] == "SCMP_ACT_ALLOW":
        return ALLOW
    return entry["errnoRet"]


def decide(doc, name, *args, arch="amd64"):
    """What the filter does with the call: allowed, or the errno. Every
    entry that matches must agree, since libseccomp does not choose
    between them by their order."""
    args = (*args, *(0,) * (6 - len(args)))
    found = {_verdict(e) for e in doc["syscalls"]
             if name in e["names"] and _applies(e, arch)
             and all(_holds(c, args) for c in e.get("args") or ())}
    if len(found) > 1:
        raise AssertionError(f"{name}{args[:3]}: entries disagree, {found}")
    return found.pop() if found else doc["defaultErrnoRet"]


def _unconditional(doc, action="SCMP_ACT_ALLOW"):
    return {n for e in doc["syscalls"] if e["action"] == action
            and not e.get("args") and not e.get("includes")
            and not e.get("excludes") for n in e["names"]}


# Arguments the conditional entries are tried with: namespace flags and
# not, upper bits, families and protocols around each block's edges.
def _clone_flags():
    every = sum(CLONE_NEW) | CLONE_NEWTIME
    return [0, SIGCHLD, CLONE_THREAD, *CLONE_NEW, CLONE_NEWTIME, every,
            CLONE_THREAD | CLONE_NEW[4], (1 << 32) | CLONE_NEW[6],
            (1 << 32) | SIGCHLD]


FAMILIES = [*range(0, 70), (1 << 32) | AF_VSOCK, (1 << 32) | 2,
            (1 << 63) | 1, MASK64]
PROTOCOLS = [*range(0, 34), (1 << 32) | NETLINK_AUDIT, MASK64]


class TestTheRulesAreOnesLibseccompReadsAsWritten(unittest.TestCase):
    def setUp(self):
        self.docs = {name: profile(name) for name in seccomp.PROFILES}

    def test_no_entry_names_an_argument_twice(self):
        for name, doc in self.docs.items():
            for entry in doc["syscalls"]:
                indexes = [c["index"] for c in entry.get("args") or ()]
                with self.subTest(profile=name, entry=entry["names"][:3]):
                    self.assertEqual(len(indexes), len(set(indexes)))

    def test_a_call_named_outright_is_in_no_other_entry(self):
        for name, doc in self.docs.items():
            seen = {}
            for entry in doc["syscalls"]:
                for call in entry["names"]:
                    seen.setdefault(call, []).append(entry)
            for call, entries in seen.items():
                outright = [e for e in entries if not e.get("args")
                            and not e.get("includes")
                            and not e.get("excludes")]
                if outright:
                    with self.subTest(profile=name, call=call):
                        self.assertEqual(entries, outright[:1])

    def test_matching_entries_agree_for_every_argument_tried(self):
        """decide() raises where they do not."""
        for name, doc in self.docs.items():
            for arch in ("amd64", "arm64", "s390x"):
                for flags in _clone_flags():
                    decide(doc, "clone", flags, arch=arch)
                    decide(doc, "clone", 0, flags, arch=arch)
                    decide(doc, "unshare", flags, arch=arch)
                for family in FAMILIES:
                    for protocol in PROTOCOLS:
                        decide(doc, "socket", family, 1, protocol,
                               arch=arch)
                for persona in (0, 8, 0x20000, 0xffffffff, 0x0400000):
                    decide(doc, "personality", persona, arch=arch)

    def test_socket_has_no_refusal_of_its_family_beside_its_allows(self):
        """The audit refusal names the protocol as well, and loads."""
        for doc in self.docs.values():
            refusals = [e for e in doc["syscalls"] if e["names"] == ["socket"]
                        and e["action"] == "SCMP_ACT_ERRNO"]
            for entry in refusals:
                self.assertEqual({c["index"] for c in entry["args"]}, {0, 2})

    def test_the_names_are_sorted_and_the_text_is_the_document(self):
        for name, doc in self.docs.items():
            for entry in doc["syscalls"]:
                self.assertEqual(entry["names"], sorted(set(entry["names"])))
            self.assertEqual(json.loads(seccomp.render(name)), doc)


class TestWhatTheProfilesRefuse(unittest.TestCase):
    def setUp(self):
        self.strict = profile("strict")
        self.debug = profile("debug")

    def test_the_default_is_strict(self):
        self.assertEqual(seccomp.DEFAULT, "strict")
        self.assertEqual(self.strict["defaultErrnoRet"], ENOSYS)

    def test_no_namespace_is_made_in_either(self):
        for doc in (self.strict, self.debug):
            for flag in (*CLONE_NEW, CLONE_NEWTIME):
                self.assertEqual(decide(doc, "unshare", flag), EPERM)
            for flag in CLONE_NEW:
                self.assertEqual(decide(doc, "clone", flag | SIGCHLD), EPERM)
                self.assertEqual(
                    decide(doc, "clone", 0, flag | SIGCHLD, arch="s390x"),
                    EPERM)
            self.assertEqual(decide(doc, "clone3"), ENOSYS)
            self.assertEqual(decide(doc, "setns"), EPERM)

    def test_a_thread_and_a_child_are_made(self):
        for doc in (self.strict, self.debug):
            threads = 0x3d0f00
            self.assertEqual(decide(doc, "clone", threads), ALLOW)
            self.assertEqual(decide(doc, "clone", SIGCHLD), ALLOW)
            self.assertEqual(decide(doc, "clone", 0, SIGCHLD, arch="s390x"),
                             ALLOW)
            self.assertEqual(decide(doc, "unshare", 0x200), ALLOW)
            for call in ("fork", "vfork", "execve", "wait4"):
                self.assertEqual(decide(doc, call), ALLOW, call)

    def test_nothing_is_mounted(self):
        for doc in (self.strict, self.debug):
            for call in seccomp.MOUNTS:
                self.assertEqual(decide(doc, call), EPERM, call)

    def test_strict_refuses_reaching_into_a_process_and_debug_allows_it(
            self):
        for call in DEBUG:
            self.assertEqual(decide(self.strict, call), EPERM, call)
            self.assertEqual(decide(self.debug, call), ALLOW, call)

    def test_debug_differs_from_strict_by_those_alone(self):
        changed = _unconditional(self.debug) ^ _unconditional(self.strict)
        self.assertEqual(changed, set(DEBUG))

        def without(doc):
            return [{**e, "names": [n for n in e["names"]
                                    if n not in DEBUG]}
                    for e in doc["syscalls"]]
        self.assertEqual(without(self.debug), without(self.strict))

    def test_the_keyring_and_io_uring_are_not_implemented(self):
        for call in ("keyctl", "add_key", "request_key", "io_uring_setup",
                     "io_uring_enter", "io_uring_register", "socketcall"):
            self.assertEqual(decide(self.strict, call), ENOSYS, call)

    def test_a_vsock_is_refused_however_its_family_is_written(self):
        for doc in (self.strict, self.debug):
            for family in (AF_VSOCK, (1 << 32) | AF_VSOCK,
                           (1 << 63) | AF_VSOCK):
                self.assertEqual(decide(doc, "socket", family, 1, 0),
                                 ENOSYS)

    def test_a_family_with_upper_bits_is_refused_not_taken_for_another(
            self):
        for family in (2, 10, AF_NETLINK, 48):
            self.assertEqual(decide(self.strict, "socket", family, 1, 0),
                             ALLOW)
            self.assertEqual(
                decide(self.strict, "socket", (1 << 32) | family, 1, 0),
                ENOSYS)

    def test_the_other_families_are_allowed(self):
        for family in range(seccomp.FAMILIES):
            if family != AF_VSOCK:
                self.assertEqual(
                    decide(self.strict, "socket", family, 1, 0), ALLOW,
                    family)

    def test_the_audit_socket_fails_as_on_a_kernel_without_audit(self):
        """EINVAL, which sudo takes as no audit; the hut holds no
        CAP_AUDIT_WRITE to use it."""
        self.assertNotIn("AUDIT_WRITE", CAPABILITIES)
        self.assertEqual(
            decide(self.strict, "socket", AF_NETLINK, 3, NETLINK_AUDIT),
            EINVAL)
        self.assertEqual(decide(self.strict, "socket", AF_NETLINK, 3, 0),
                         ALLOW)
        self.assertEqual(
            decide(profile("strict", (*CAPABILITIES, "AUDIT_WRITE")),
                   "socket", AF_NETLINK, 3, NETLINK_AUDIT), ALLOW)

    def test_an_unknown_name_is_refused(self):
        with self.assertRaises(ValueError):
            profile("unconfined")


if __name__ == "__main__":
    unittest.main()
