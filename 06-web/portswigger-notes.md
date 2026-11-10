# PortSwigger Web Security Academy - Research Notes

Stage 7 - Web Security. Notes from the PortSwigger Web Security
Academy labs: payload, root cause and fix for each lab, followed by
a code-level summary per vulnerability type.

## Contents

- **Exercise 1:** SQL Injection (2 labs)
- **Exercise 2:** XSS - reflected vs. stored (2 labs)
- **Exercise 3:** Broken Access Control and SSRF (2 labs)
- **Summary:** mechanism and fix for each vulnerability type

The full report for the SSRF finding is in [vulnerability-report.md](./vulnerability-report.md).

---

## Exercise 1: SQL Injection

### Lab 1: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

**Link:** https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data

**Payload:**

First attempt (worked partially, not counted as Solved by the system):
```
category=Accessories'--
```
Why it wasn't counted: this payload only reveals unreleased products
within the Accessories category, while the lab checks for a specific
product that was assigned to a different category.

Final payload (counted as Solved):
```
category=' OR 1=1--
```

**Root cause:**
The server builds the SQL query by string concatenation, instead of
using a parameterized query. The user's input is inserted directly
into the query text, so a single quote character breaks the syntax,
and `OR 1=1` makes the WHERE condition always true for every row,
which also exposes products that were supposed to be hidden
(`released = 1`).

**Suggested fix:** Use parameterized queries (prepared statements),
so that the input is passed to the database as a parameter separate
from the query, and is never interpreted as SQL code.

---

### Lab 2: SQL injection vulnerability allowing login bypass

**Link:** https://portswigger.net/web-security/sql-injection/lab-login-bypass

**Payload:**
```
username=administrator'--
password=anything
```

**Root cause:**
The exact same issue - string concatenation when building the
authentication query. The `--` cancels out everything that follows
it in the query, including `AND password = '...'`, so the query
returns the administrator's row with no actual password check at
all.

**Suggested fix:** Parameterized queries, same as in the previous
lab.

---

## Exercise 2: Cross-Site Scripting (XSS)

### Lab 1: Reflected XSS into HTML context with nothing encoded

**Link:** https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded

**Payload:**
```
<script>alert(1)</script>
```
(entered into the site's search box)

**Root cause:**
The server returns the search string back inside the HTML body of
the response **without encoding** special characters such as `<`
and `>`. As a result, the victim's browser receives the `<script>`
tag as a legitimate part of the page's HTML, not as text, and
executes it. This is **reflected** XSS - the malicious input comes
from the request itself (a URL parameter) and comes back
("reflects") immediately in that same response, without being
stored on the server side.

**Suggested fix:** HTML encoding (HTML entity encoding) of all user
input before inserting it into the page body - so that `<` becomes
`&lt;`, etc., and the browser displays it as plain text rather than
as executable code.

---

### Lab 2: Stored XSS into HTML context with nothing encoded

**Link:** https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded

**Payload:**
```
<script>alert(1)</script>
```
(entered into the Comment box on a post page)

**Root cause:**
Same as the previous lab - the comment is stored and displayed back
without HTML encoding. The key difference is **where the
vulnerability sits in the data flow**: here the input **is stored**
in the server's database (hence "stored"), and is served again to
anyone who loads the post page in the future - with no further
action needed on their part. In reflected XSS, by contrast, the
input is not stored anywhere; it exists only within a single
request-response pair, so the attack requires tricking a specific
victim into clicking a pre-crafted link that contains the payload.

This difference makes stored XSS more severe: it affects every
visitor to the page automatically, with no dependence on social
engineering or on clicking a malicious link.

**Suggested fix:** HTML encoding when displaying the stored content
(not just the reflected input), applied everywhere that content
saved by users is shown back to others.

---

## Exercise 3: Broken Access Control and SSRF

### Lab: URL-based access control can be circumvented

**Link:** https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented
**Level:** Practitioner

**Payload:**

Step 1 - confirm access to the admin panel:
```
GET / HTTP/2
X-Original-URL: /admin
```

Step 2 - actually perform the protected action (deleting user
carlos). The path on the normal request line keeps the query
string, while the header carries only the new path, without the
parameters:
```
GET /?username=carlos HTTP/2
X-Original-Url: /admin/delete
```
Result: `"User deleted successfully!"`, the lab moved to Solved.

**What enabled the vulnerability:**
The architecture has two separate server components: a proxy/gateway
that checks permissions based on the visible path on the request
line (`GET /`, not `/admin`, so it lets the request through), and an
internal application server that actually routes the request based
on the `X-Original-URL` header, without performing its own
permission check - it trusts that the proxy in front of it has
already filtered out unauthorized access. Each component assumes the
other one is responsible for the permission check, so in practice
neither one actually checks. An attacker who knows about the header
can send a request to an "innocent-looking" path (`/`) and cause it
to actually be routed to a protected destination, bypassing the
permission layer.

**Suggested fix:** Permission checks must be performed **in the
application server itself**, based on the real destination it
actually routes to - not relying on an external component (proxy)
that only checks the visible path. Rule of thumb: permissions should
be checked as close as possible to the protected resource itself,
not in a layer that comes before it and may have a different picture
(header, internal routing) than what actually happens afterward.

---

### Lab: Basic SSRF against another back-end system

**Link:** https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system
**Level:** Apprentice

**Payload:**

Step 1 - scanning the internal network (192.168.0.0/24) through the
`stockApi` parameter in a POST request to `/product/stock`, using
Burp Intruder (Sniper, Numbers 1-255 on the last octet):
```
stockApi=http://192.168.0.§1§:8080/admin
```
Sorting the results by Status ascending revealed one address
(`192.168.0.226`) that returned `200 OK` - while all other
addresses returned 500 (no server) or other generic errors.

Step 2 - performing the damaging action (deleting carlos) through
that same address:
```
stockApi=http://192.168.0.226:8080/admin/delete?username=carlos
```
Result: `302 Found` with
`Location: http://192.168.0.226:8080/admin` - the request was
processed by the internal admin interface, and the lab moved to
Solved.

**Root cause:**
The public server accepts an address (`stockApi`) from the user
**with no restriction whatsoever**, and makes its own HTTP request to
it. Because the public server also sits on the internal network
(192.168.0.0/24), it can reach internal interfaces that an external
attacker could never access directly. In effect, the attacker turns
the server into an unwilling "messenger": it asks the server to make
a request to a sensitive internal resource (an admin panel), and the
server does so because it doesn't check **where** it is actually
connecting to - it just accepts the destination address as free
input. The internal admin panel, for its part, trusts any request
that arrives from the public server (since it's "internal" and
assumed to be trustworthy), and therefore requires no further
authentication.

**Suggested fix:** A strict allow-list of the addresses/services that
`stockApi` is permitted to point to (not a blacklist of what's
forbidden - blacklists are easy to bypass). Ideally: don't accept an
external address at all; instead pass only an identifier (like
`storeId`) that the server itself maps to the fixed internal address.
In addition, the internal admin interface itself should require its
own authentication, rather than relying on the assumption that only
"internal" components can reach it.

---

## Summary - Mechanism and Fix for Each Vulnerability Type

### 1. SQL Injection

**How it causes the failure:**
The application builds a SQL query by **string concatenation** -
pasting the user's input directly into the query text before it is
sent to the database:
```python
query = "SELECT * FROM products WHERE category = '" + category + "'"
```
The SQL engine only receives the final string, and has no way of
knowing which parts of it are "code the developer wrote" and which
are "input the user entered." If the input contains characters like
a single quote (`'`), they change the **structure** of the query
itself - not just the value it's searching for. This lets an
attacker add conditions (`OR 1=1`), cancel out parts of the query
(`--`), and even extract real data or bypass authentication.

**How it's actually fixed:**
Use **Parameterized Queries** (also called Prepared Statements). The
query is sent to the database as a fixed "template" with
placeholders, and the values are sent **separately**, as parameters:
```python
cursor.execute(
    "SELECT * FROM products WHERE category = %s",
    (category,)
)
```
The database compiles the structure of the query **once**, before it
ever sees the value of `category`. From then on, anything that
arrives as a parameter is treated by default as a plain text value -
even if it contains quotes, dashes, or any other character, it
cannot change the structure of the query.

Simply "filtering" or "sanitizing" dangerous characters (a blacklist)
is not enough - there will always be ways around it; the only
reliable solution is a structural separation between code and data.

---

### 2. Cross-Site Scripting (XSS)

**How it causes the failure:**
The application inserts input (either the user's own, or another
user's input that was saved in the database) **directly** into the
body of an HTML page, without encoding special characters such as
`<` and `>`. The browser that receives the page **interprets** every
`<...>` as a legitimate HTML tag - it cannot tell the difference
between "text someone typed" and "code the developer wrote." If the
input is `<script>...</script>`, the browser simply runs it, with
all of the site's privileges (including reading cookies, performing
actions as the logged-in user, etc.). The difference between
reflected and stored is only **where in the data flow** this
happens: reflected = the input comes back immediately from the same
request; stored = the input is saved on the server and served to
every future visitor.

**How it's actually fixed:**
**Output encoding**, according to the context in which the input is
displayed. When inserting text into an HTML body, special characters
are encoded:
```
<  →  &lt;
>  →  &gt;
"  →  &quot;
'  →  &#x27;
```
This way the browser displays the content **as plain text**, not as
executable code. In most modern frameworks (React, Vue, Django
templates, etc.) this happens **automatically** by default - the
danger mainly arises when this is deliberately "bypassed" (like
`dangerouslySetInnerHTML` in React). As an additional defense, it's
recommended to add a Content-Security-Policy (CSP) header that
restricts in advance which scripts are allowed to run on the page, so
that even if malicious input does get in, the browser will still
refuse to run it.

---

### 3. Broken Access Control

**How it causes the failure:**
The application checks permissions **in the wrong place**, or
doesn't check them at all at the point where it **actually performs**
the sensitive action. Examples of the mechanism: checking permissions
only in the user interface (the "Admin" link simply isn't shown, but
the route itself is still reachable), or relying on one component
(like a proxy) that checks based on one representation of the
request (the visible path), while a different component actually
performs the action based on a **different** representation of it (a
header the attacker controls). Each component "assumes" someone else
already checked - and in practice, no one checks in the right place.

**How it's actually fixed:**
Permission checks **must** also happen on the server, **right
before** the sensitive action itself is performed - not in an
earlier layer (proxy, UI). For example, every handler that deals
with a protected action checks itself:
```python
@app.route("/admin/delete")
def delete_user():
    if not current_user.is_admin:
        return "Forbidden", 403
    ...  # only after the check, perform the action
```
Guiding principle: **Deny by default** - every resource is blocked by
default, and access is granted only explicitly, based on role
(role-based access control), instead of trying to "block" specific
routes (you can always miss one). In addition, the permission check
should be made against the **actual route/resource that is being
performed**, not against an external representation of it that an
attacker can change (such as a custom header).

---

### 4. SSRF (Server-Side Request Forgery)

**How it causes the failure:**
The application accepts an address (a URL, a host, or parts of one)
from the user and uses it to make an HTTP request **of its own**,
without restricting where it is allowed to connect. Because the
server itself is also located on internal networks that aren't
reachable from outside, an attacker can "politely ask" the server to
reach internal resources on their behalf (admin interfaces, cloud
metadata endpoints, internal databases) that the attacker could never
reach directly. The server effectively becomes an unwitting proxy for
the attacker.

**How it's actually fixed:**
A strict **allow-list** of permitted destinations - not a blacklist
(easy to bypass with an encoded IP, a redirect, DNS rebinding, etc.).
The safest approach: don't accept a free-form address from the user
at all; instead accept only an **identifier** (like `storeId=3`) that
the server maps itself, server-side, to a fixed, predefined internal
address:
```python
ALLOWED_STORES = {"3": "http://192.168.0.5:8080/internal/stock"}
url = ALLOWED_STORES.get(store_id)
if not url:
    return "Invalid store", 400
```
As an additional defense-in-depth measure: network segmentation, so
that the public server cannot reach the sensitive internal network at
all, and authentication of its own on every internal interface (not
relying on the assumption that "only internal requests" reach it).