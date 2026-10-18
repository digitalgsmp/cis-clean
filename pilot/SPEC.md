# Pilot task — parse_duration

Author a single self-contained Python file: `duration.py`.

It must define exactly one public function:

    def parse_duration(text: str) -> int

It converts a duration string to a whole number of SECONDS.

Accepted format: one or more ASCII digits followed by exactly one unit
character, with no whitespace, no sign, and nothing else.

    s = seconds, m = minutes (60s), h = hours (3600s), d = days (86400s)

Examples that must succeed:
    "0s" -> 0,  "90s" -> 90,  "5m" -> 300,  "2h" -> 7200,  "1d" -> 86400,
    "120m" -> 7200

It must raise ValueError for anything else, including: the empty string,
a missing unit ("90"), an unknown unit ("90x"), an uppercase unit ("90S"),
whitespace anywhere (" 90s", "90s "), a negative or signed value ("-5m",
"+5m"), a non-integer value ("1.5h"), a missing number ("s"), more than one
unit ("1m30s"), and a non-str argument (raise ValueError, not TypeError).

Constraints: standard library only, no imports beyond `re` if needed, no I/O,
no printing, no `if __name__ == "__main__"` block, no classes.
