#!/usr/bin/python

from __future__ import print_function

import os
import json
import sys
import re

# Works for rspamd version
__version__ = "1.4.1"

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

# Rule format: FOO_BAR(47.11){additional_info}
RULE = "([0-9A-Z_]+)\((-?[0-9.]+)\)(\{[^\{]*\})"

rules = dict()

def main():
    table = dict()
    table_sorted = list()
    records = list()
    total_pos = total_neg = 0

    normal = 0
    add_header = 0
    greylist = 0
    reject = 0
    soft_reject = 0
    subject = 0
    total_msgs = 0

    prog = re.compile(PATTERN)
    rule_prog = re.compile(RULE)

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
                elif action == "subject":
                    subject += 1
                elif action == "soft reject":
                    soft_reject += 1
                elif action == "reject":
                    reject += 1

                for cur in iter(rule_prog.findall(result.group(2))):
                    rule_name = cur[0]
                    rule_score = float(cur[1])
                    rule_extra = cur[2]  # Currently unused
                    if rule_name in table:
                        old = table[rule_name]
                        old['cnt'] += 1
                        table[rule_name] = old
                    else:
                        new = dict(cnt=1, score=rule_score)
                        table[rule_name] = new

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

    print("\nTotal messages scanned:\t{}\t\t100%".format(total_msgs))
    print("-" * 78)
    print("No action:\t\t{}\t\t{:.2f}%"
          "\nGreylist:\t\t{}\t\t{:.2f}%"
          "\nAdd header:\t\t{}\t\t{:.2f}%"
          "\nSubject:\t\t{}\t\t{:.2f}%"
          "\nSoft reject:\t\t{}\t\t{:.2f}%"
          "\nReject:\t\t\t{}\t\t{:.2f}%"
          .format(
            normal, 
            100.0 * normal / total_msgs if normal > 0 else 0.0, 
            greylist, 
            100.0 * greylist / total_msgs if greylist > 0 else 0.0,
            add_header, 
            100.0 * add_header / total_msgs if add_header > 0 else 0.0,
            subject, 
            100.0 * subject / total_msgs if subject > 0 else 0.0,
            soft_reject, 
            100.0 * soft_reject / total_msgs if soft_reject > 0 else 0.0,
            reject, 
            100.0 * reject / total_msgs if reject > 0 else 0.0))

    print("\nHam scores:")
    print("%\tQuantity\tScore\t\tTest")
    print("-" * 78)
    for test in table_sorted:
        try:
            if float(test[1]) <= 0.0:
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
    print("-" * 78)
    for test in table_sorted:
        try:
            if float(test[1]) > 0.0:
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

