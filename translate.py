import sys
import re


def parse_iptables(pairs):
    MAP = {
        "-A": "chain",
        "-p": "protocol",
        "-s": "src-address",
        "-d": "dst-address",
        "-i": "in-interface",
        "-o": "out-interface",
        "--tcp-flags": "tcp-flags",
        "--state" : "connection-state",
        "--dports": "dst-ports",
        "--dport": "dst-port",
        "--sports": "src-ports",
        "--sport": "src-port",
        "--to-source": "to-source",
        "--to-destination": "to-destination",
        "-j": "action",
        "-m": "match",
        "--comment": "comment"
    }

    rule = {}
    for k, v in pairs:
        if k not in MAP:
            print("Unsupported parameter", k)
            continue
        
        name = MAP[k]
        rule[name] = v

    return rule


class RuleGenerator:
    def transform(self, rule):
        for f in self.fields:
            if f in rule:
                if hasattr(self, f):
                    yield getattr(self, f)(rule[f])
                else:
                    yield (f, rule[f])


class MikrotikGenerator(RuleGenerator):
    fields = [
        "chain", "protocol", "src-address", "dst-address", 
        "dst-port", "src-port", "tcp-flags", "connection-state", 
        "in-interface", "out-interface", "action", "to-address",
        "comment"
    ]

    def action(self, value):
        return "action", value.lower()


def generate_mikrotik(rule):
    cmd = "ip firewall filter add"
    generator = MikrotikGenerator()
    pairs = generator.transform(rule)
    cmd += " ".join("%s=%s" % p for p in pairs)

    return cmd


def parse_rules(fpath):
    lines = open(fpath).readlines()
    pattern = re.compile(r'''((?:[^ "']|"[^"]*"|'[^']*')+)''')

    for line in lines:
        tokens = pattern.split(line.strip())[1::2]

        if tokens[0] != '-A':
            print("Unsupported rule", line)
            continue

        pairs = zip(tokens[0::2], tokens[1::2])
        yield parse_iptables(pairs)


rules = parse_rules("iptables.txt")
for rule in rules:
    print(generate_mikrotik(rule))
