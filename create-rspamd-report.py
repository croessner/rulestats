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
SORT_KEY = SORT_QTY

# Search pattern for mail.log
PATTERN = (".+ task; rspamd_task_write_log: id: <.+>, "
           "qid: <[a-zA-Z0-9]+>, ip: .+, from: <.+>, \("
           "default:.+ \((.+)\): \[.+/.+\] \[(.+)\]"
           "\), .+$")

rules = dict()

def collect_info(record):
    for rule, ruledef in record.iteritems():
        rules[rule] = ruledef["weight"]

def main():
    table = dict()
    table_sorted = list()
    records = list()
    total_pos = total_neg = 0

    normal = 0
    add_header = 0
    greylist = 0
    reject = 0
    total_msgs = 0

    config = json.load(sys.stdin)["metric"]["group"]
    prog = re.compile(PATTERN)

    for group in iter(config):
        for rawsym in group.itervalues():
            sym = rawsym["symbol"]
            if isinstance(sym, list):
                for subsym in iter(sym):
                    collect_info(subsym)
            if isinstance(sym, dict):
                collect_info(sym)

    res_from_log = False
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
                total_msgs += 1

                action = result.group(1)
                if action == "no action":
                    normal += 1
                elif action == "add header":
                    add_header += 1
                elif action == "greylist":
                    greylist += 1
                elif action == "reject":
                    reject += 1

                cur = result.group(2).split(",")
                for check in cur:
                    if "(" in check:
                        value = float(check.split("(")[1].split(")")[0])
                        res_from_log = True
                    if check in table:
                        old = table[check]
                        old['cnt'] += 1
                        table[check] = old
                    else:
                        try:
                            if res_from_log:
                                new = dict(cnt=1, score=value)
                            else:
                                new = dict(cnt=1, score=rules[check])
                            table[check] = new
                        except KeyError:
                            pass

    for k, v in table.items():
        if v['cnt'] < REQ_MIN_QTY:
            continue
        records.append([v['cnt'], v['score'], k])
        table_sorted = sorted(records,
                              key=lambda x: x[SORT_KEY],
                              reverse=True)

    for test in table_sorted:
        try:
            if float(test[1]) >= 0.0:
                total_pos += int(test[0])
            else:
                total_neg += int(test[0])
        except ValueError:
            print("ValueError: %s" % test, file=sys.stderr)

    print("Scan statistics:")
    print("\nTotal: {}\nAdd header: {}\nGreylist: {}\nReject: {}\nNo action: {}"
          .format(total_msgs, add_header, greylist, reject, normal))
    print("\nHam scores:")
    print("%\tQuantity\tScore\t\tTest")
    print("-" * 79)
    for test in table_sorted:
        try:
            if float(test[1]) < 0.0:
                if res_from_log:
                    tmpname = test[2].split("(")[0]
                    test[2] = tmpname
                print(("%.2f%%\t%s\t\t%s\t\t%s"
                      % ((100.0 * test[0] / total_neg),
                         test[0], test[1], test[2])))
        except ValueError:
            print("ValueError: %s" % test, file=sys.stderr)

    print("\nSpam scores:")
    print("%\tQuantity\tScore\t\tTest")
    print("-" * 79)
    for test in table_sorted:
        try:
            if float(test[1]) >= 0.0:
                if res_from_log:
                    tmpname = test[2].split("(")[0]
                    test[2] = tmpname
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

