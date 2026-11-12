"""Summarize offline DNS query exports and flag high NXDOMAIN ratios or unusually long first labels."""
import argparse
from collections import Counter,defaultdict
import csv
import ipaddress
import json
from pathlib import Path

def analyze(rows,min_queries=5,nxdomain_ratio=0.6,long_label=40):
    if min_queries<1 or not 0<=nxdomain_ratio<=1 or not 1<=long_label<=63:
        raise ValueError('invalid thresholds')
    groups=defaultdict(list)
    for row in rows:
        client=str(ipaddress.ip_address(row['client']))
        query=row['query'].rstrip('.').lower()
        labels=query.split('.')
        if not query or len(query)>253 or any(not label or len(label)>63 for label in labels):
            raise ValueError('invalid query length')
        rcode=row['rcode'].upper()
        if rcode not in {'NOERROR','NXDOMAIN','SERVFAIL','REFUSED'}:
            raise ValueError('unsupported rcode')
        groups[client].append((query,rcode))
    reports=[]
    for client,queries in sorted(groups.items()):
        counts=Counter(rcode for _,rcode in queries)
        ratio=counts['NXDOMAIN']/len(queries)
        long_count=sum(len(query.split('.')[0])>=long_label for query,_ in queries)
        reasons=[]
        if len(queries)>=min_queries and ratio>=nxdomain_ratio: reasons.append('high_nxdomain_ratio')
        if long_count: reasons.append('long_first_label')
        reports.append(dict(client=client,queries=len(queries),unique_queries=len({q for q,_ in queries}),nxdomain_ratio=round(ratio,3),long_label_count=long_count,reasons=reasons))
    return reports

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path)
    parser.add_argument('--min-queries',type=int,default=5)
    args=parser.parse_args()
    try:
        with args.input.open(encoding='utf-8',newline='') as handle:
            print(json.dumps(analyze(csv.DictReader(handle),args.min_queries),indent=2))
    except (OSError,ValueError,KeyError,TypeError) as exc:
        parser.exit(2,f'error: {exc}\n')

if __name__=='__main__': main()
