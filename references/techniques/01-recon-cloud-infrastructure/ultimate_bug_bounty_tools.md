# Ultimate Bug Bounty Tools Guide

# 1. Subdomain Enumeration

## Subfinder
Repository:
https://github.com/projectdiscovery/subfinder

### Description
Fast passive subdomain enumeration tool developed by ProjectDiscovery.

### Common Usage
```bash
subfinder -d target.com -silent
```

### Important Flags
| Flag | Explanation |
|---|---|
| `-d` | Target domain |
| `-silent` | Clean output only |
| `-all` | Use all sources |
| `-recursive` | Recursive subdomain enumeration |
| `-o` | Output file |

### Example
```bash
subfinder -d hackerone.com -all -silent -o subs.txt
```

---

## Amass
Repository:
https://github.com/owasp-amass/amass

### Description
Advanced subdomain enumeration and attack surface mapping framework.

### Common Usage
```bash
amass enum -passive -d target.com
```

### Important Flags
| Flag | Explanation |
|---|---|
| `enum` | Start enumeration |
| `-passive` | Passive mode |
| `-active` | Active enumeration |
| `-brute` | Bruteforce subdomains |
| `-src` | Show source of discovery |
| `-ip` | Show resolved IPs |

### Example
```bash
amass enum -active -brute -d target.com
```

---

## Assetfinder
Repository:
https://github.com/tomnomnom/assetfinder

### Description
Lightweight passive subdomain discovery tool.

### Usage
```bash
assetfinder --subs-only target.com
```

### Important Flags
| Flag | Explanation |
|---|---|
| `--subs-only` | Show only subdomains |

---

# 2. Live Host Discovery

## httpx
Repository:
https://github.com/projectdiscovery/httpx

### Description
HTTP probing tool used heavily in recon pipelines.

### Usage
```bash
cat subs.txt | httpx -silent
```

### Important Flags
| Flag | Explanation |
|---|---|
| `-silent` | Minimal output |
| `-title` | Fetch page title |
| `-tech-detect` | Detect technologies |
| `-status-code` | Show status code |
| `-follow-redirects` | Follow redirects |
| `-threads` | Number of threads |

### Example
```bash
cat subs.txt | httpx -title -tech-detect -status-code
```

---

## httprobe
Repository:
https://github.com/tomnomnom/httprobe

### Description
Fast HTTP/HTTPS service checker.

### Usage
```bash
cat subs.txt | httprobe
```

---

# 3. Crawlers and URL Discovery

## Katana
Repository:
https://github.com/projectdiscovery/katana

### Description
Modern web crawler with JavaScript parsing support.

### Usage
```bash
katana -u https://target.com
```

### Important Flags
| Flag | Explanation |
|---|---|
| `-u` | Target URL |
| `-jc` | JavaScript crawling |
| `-silent` | Minimal output |
| `-d` | Crawl depth |
| `-kf` | Known file crawling |
| `-headless` | Browser crawling |

### Example
```bash
katana -u https://target.com -jc -d 5
```

---

## hakrawler
Repository:
https://github.com/hakluke/hakrawler

### Description
Fast web crawler using GoColly.

### Usage
```bash
echo https://target.com | hakrawler
```

---

## gau
Repository:
https://github.com/lc/gau

### Description
Fetches URLs from Wayback Machine and Common Crawl.

### Usage
```bash
gau target.com
```

### Important Flags
| Flag | Explanation |
|---|---|
| `--threads` | Thread count |
| `--subs` | Include subdomains |
| `--blacklist` | Exclude extensions |

### Example
```bash
gau --subs target.com
```

---

## waymore
Repository:
https://github.com/xnl-h4ck3r/waymore

### Description
Advanced archive and URL collection tool.

### Usage
```bash
waymore -i target.com
```

---

# 4. JavaScript Analysis

## LinkFinder
Repository:
https://github.com/GerbenJavado/LinkFinder

### Description
Extract endpoints and links from JavaScript files.

### Usage
```bash
python linkfinder.py -i app.js -o cli
```

### Important Flags
| Flag | Explanation |
|---|---|
| `-i` | Input JS file |
| `-o` | Output mode |

---

## xnLinkFinder
Repository:
https://github.com/xnl-h4ck3r/xnLinkFinder

### Description
Advanced endpoint extractor from JS and responses.

### Usage
```bash
python xnLinkFinder.py -i urls.txt
```

---

## SecretFinder
Repository:
https://github.com/m4ll0k/SecretFinder

### Description
Searches JS files for secrets and API keys.

### Usage
```bash
python SecretFinder.py -i https://target.com/app.js -o cli
```

---

## JSParser
Repository:
https://github.com/nahamsec/JSParser

### Description
Extract URLs and secrets from JavaScript files.

### Usage
```bash
python jsparser.py urls.txt
```

---

# 5. JavaScript Deobfuscation

## de4js
Repository:
https://github.com/lelinhtinh/de4js

### Description
JavaScript deobfuscation and unpacking tool.

### Features
- Packer decoding
- Obfuscator.io support
- JJEncode support
- AAEncode support

---

## JSNice
Website:
http://www.jsnice.org

### Description
AI-assisted JavaScript beautification and variable recovery.

---

# 6. Secret Extraction

## TruffleHog
Repository:
https://github.com/trufflesecurity/trufflehog

### Description
Advanced secret scanning framework.

### Usage
```bash
trufflehog github --repo https://github.com/org/repo
```

### Important Flags
| Flag | Explanation |
|---|---|
| `github` | GitHub mode |
| `--repo` | Repository target |
| `filesystem` | Scan local files |
| `git` | Scan git history |

### Example
```bash
trufflehog filesystem .
```

---

## Gitleaks
Repository:
https://github.com/gitleaks/gitleaks

### Description
Fast secret detection tool.

### Usage
```bash
gitleaks detect -s .
```

### Important Flags
| Flag | Explanation |
|---|---|
| `detect` | Start scanning |
| `-s` | Source directory |
| `--report-path` | Save report |

---

## GitDorker
Repository:
https://github.com/obheda12/GitDorker

### Description
GitHub dorking automation tool.

### Usage
```bash
python GitDorker.py -tf tokens.txt -q target.com
```

---

# 7. Fuzzing and Content Discovery

## ffuf
Repository:
https://github.com/ffuf/ffuf

### Description
Fast web fuzzer.

### Usage
```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt
```

### Important Flags
| Flag | Explanation |
|---|---|
| `-u` | Target URL |
| `-w` | Wordlist |
| `-mc` | Match status code |
| `-fc` | Filter status code |
| `-fs` | Filter size |
| `-t` | Threads |

### Example
```bash
ffuf -u https://target.com/FUZZ -w raft.txt -mc 200,403
```

---

## dirsearch
Repository:
https://github.com/maurosoria/dirsearch

### Description
Recursive directory and file brute forcing tool.

### Usage
```bash
python dirsearch.py -u https://target.com
```

---

## feroxbuster
Repository:
https://github.com/epi052/feroxbuster

### Description
Rust-based content discovery tool.

### Usage
```bash
feroxbuster -u https://target.com
```

---

# 8. Vulnerability Scanning

## Nuclei
Repository:
https://github.com/projectdiscovery/nuclei

### Description
Template-based vulnerability scanner.

### Usage
```bash
nuclei -u https://target.com
```

### Important Flags
| Flag | Explanation |
|---|---|
| `-u` | Single target |
| `-l` | Target list |
| `-t` | Templates |
| `-severity` | Filter by severity |
| `-rl` | Rate limit |
| `-o` | Output file |

### Example
```bash
nuclei -l live.txt -severity critical,high
```

---

# 9. Screenshotting and Visual Recon

## gowitness
Repository:
https://github.com/sensepost/gowitness

### Description
Take screenshots of websites at scale.

### Usage
```bash
gowitness scan file -f urls.txt
```

---

## EyeWitness
Repository:
https://github.com/FortyNorthSecurity/EyeWitness

### Description
Visual reconnaissance framework.

### Usage
```bash
python EyeWitness.py --web -f urls.txt
```

---

# 10. Automation Frameworks

## reconFTW
Repository:
https://github.com/six2dez/reconftw

### Description
Full bug bounty automation framework.

### Features
- Subdomain enum
- Crawling
- Nuclei integration
- Screenshotting
- Takeover checks
- JS analysis

### Usage
```bash
./reconftw.sh -d target.com
```

---

## BBH-Recon
Repository:
https://github.com/RemmyNine/BBH-Recon

### Description
Methodology-focused bug bounty framework.

---

## Ars0n Framework
Repository:
https://github.com/R-s0n/ars0n-framework-v2

### Description
Modern integrated bug bounty recon framework.

---

# Recommended Elite Bug Bounty Stack

```text
Subfinder
Amass
httpx
Katana
gau
waymore
LinkFinder
xnLinkFinder
TruffleHog
Gitleaks
ffuf
Nuclei
gowitness
reconFTW
```

# Suggested Workflow

```text
Subdomains -> Live Hosts -> Crawling -> JS Analysis -> Secrets -> Fuzzing -> Vulnerability Scanning
```
