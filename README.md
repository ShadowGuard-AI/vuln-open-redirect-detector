# vuln-Open-Redirect-Detector
Detects open redirect vulnerabilities by providing a URL and a list of redirect URLs. The tool follows the redirect chain of the provided URL and checks every hop, not just the final URL, against the list. A hop matches when its parsed origin (scheme, host, and port) equals a listed URL's origin, and, when the listed URL names a path, the hop path starts with that path. A chain that lands on an error status is still judged on its hops. If the target cannot be reached or the input is invalid, the tool exits non-zero and reports no verdict. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowStrikeHQ/vuln-open-redirect-detector`

## Usage
`./vuln-open-redirect-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `-t`: No description provided

## License
Copyright (c) ShadowStrikeHQ
