"""Review captured HTTP response headers offline and explain actionable browser-hardening gaps."""
import re

def analyze(data):
    headers = {k.lower(): str(v) for k,v in data['headers'].items()}
    findings = []
    def add(rule, message):
        findings.append(dict(kind=rule, message=message))
    if data.get('https', True):
        hsts = headers.get('strict-transport-security', '')
        match = re.search(r'(?:^|;)\s*max-age\s*=\s*(\d+)(?:;|$)', hsts, re.I)
        if not match or int(match[1]) < 15552000:
            add('hsts', 'Set a considered HSTS policy with at least 180 days after deployment validation.')
    csp = headers.get('content-security-policy', '')
    directives = {p.strip().split()[0].lower():p.strip().split()[1:] for p in csp.split(';') if p.strip()}
    if not directives:
        add('csp_missing', 'Define an enforcing Content-Security-Policy.')
    else:
        scripts = directives.get('script-src', directives.get('default-src', []))
        if not scripts or any(x in scripts for x in ('*', "'unsafe-inline'", "'unsafe-eval'")):
            add('csp_scripts', 'Constrain script sources; prefer nonces or hashes.')
    ancestors = directives.get('frame-ancestors', [])
    if not ancestors and headers.get('x-frame-options','').upper() not in ('DENY','SAMEORIGIN'):
        add('framing', 'Restrict framing with frame-ancestors or X-Frame-Options.')
    if headers.get('x-content-type-options','').lower() != 'nosniff':
        add('nosniff', 'Set X-Content-Type-Options: nosniff.')
    if headers.get('referrer-policy','').lower() not in ('no-referrer','same-origin','strict-origin','strict-origin-when-cross-origin'):
        add('referrer', 'Choose a restrictive Referrer-Policy.')
    return findings


def main():
    import argparse, json, sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='path to JSON input, or - for stdin')
    args = parser.parse_args()
    try:
        if args.input == '-':
            data = json.load(sys.stdin)
        else:
            with open(args.input, encoding='utf-8') as stream:
                data = json.load(stream)
        result = analyze(data)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (ValueError, KeyError, TypeError, OSError, OverflowError) as error:
        print('Invalid input: '+str(error), file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
