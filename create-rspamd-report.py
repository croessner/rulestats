#!/usr/bin/python

from __future__ import print_function

import os
import json
import sys
import re

# Macros for SORT_KEY
SORT_QTY = 0        # Absolute number of hits that a SA rule has gained
SORT_SCORE = 1      # The score of a SA rule

# Minimum required records, a rule was hit
REQ_MIN_QTY = 2

# Sort table
SORT_KEY = SORT_SCORE

BAR_LEN = 78

# Search pattern for mail.log
PATTERN = ("^[a-zA-Z]{3} [0-9: ]{11} [a-zA-Z0-9]+ rspamd\[[0-9]{1,5}\]: "
           ".+ task; rspamd_task_write_log: id: <.+>, "
           "qid: <[a-zA-Z0-9]+>, ip: .+, from: <.+>, \("
           "default:.+ \(.+\): \[.+/.+\] \[(.+)\]"
           "\), .+$")

rules = dict()


def collect_info(record):
    for rule, ruledef in record.items():
        rules[rule] = ruledef["weight"]


def main():
    table = dict()
    table_sorted = list()
    records = list()
    total_pos = total_neg = 0

    config = json.load(sys.stdin)["metric"]["group"]
    prog = re.compile(PATTERN)

    for group in iter(config):
        for rawsym in group.values():
            sym = rawsym["symbol"]
            if isinstance(sym, list):
                for subsym in iter(sym):
                    collect_info(subsym)
            if isinstance(sym, dict):
                collect_info(sym)

    with open(sys.argv[1]) as f:
        while True:
            try:
                line = f.readline()
            except UnicodeDecodeError:
                continue
            if line == "":
                break
            result = prog.match(line)
            if result is not None:
                cur = result.group(1).split(",")
                for check in cur:
                    if check in table:
                        old = table[check]
                        old['cnt'] += 1
                        table[check] = old
                    else:
                        try:
                            new = dict(cnt=1, score=rules[check])
                            table[check] = new
                        except KeyError:
                            pass

    for k, v in table.items():
        if v['cnt'] < REQ_MIN_QTY:
            continue
        records.append([v['cnt'], v['score'], k])
        table_sorted = sorted(records,
                              key=lambda r: r[SORT_KEY],
                              reverse=True)

    for test in table_sorted:
        try:
            if float(test[1]) >= 0.0:
                total_pos += int(test[0])
            else:
                total_neg += int(test[0])
        except ValueError:
            print("ValueError: %s" % test, file=sys.stderr)

    print("Ham scores:")
    print("%\tQuantity\tScore\t\tTest")
    print("-" * BAR_LEN)
    for test in table_sorted:
        try:
            if float(test[1]) < 0.0:
                print(("%.2f%%\t%s\t\t%s\t\t%s"
                      % ((100.0 * test[0] / total_neg),
                         test[0], test[1], test[2])))
        except ValueError:
            print("ValueError: %s" % test, file=sys.stderr)

    print("\nSpam scores:")
    print("%\tQuantity\tScore\t\tTest")
    print("-" * BAR_LEN)
    for test in table_sorted:
        try:
            if float(test[1]) >= 0.0:
                print(("%.2f%%\t%s\t\t%s\t\t%s"
                      % ((100.0 * test[0] / total_pos),
                         test[0], test[1], test[2])))
        except ValueError:
            print("ValueError: %s" % test, file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__file__ + " logfile")
        sys.exit(os.EX_USAGE)

    if not os.path.exists(sys.argv[1]):
        print("Unable to access log file " + sys.argv[1])
        sys.exit(os.EX_OSERR)

    main()

    sys.exit(os.EX_OK)
