---
title: Security (Theater) Questions
excerpt: In the time before improved multi-factor authentication schemes, there were security questions.
date: 2021-09-16
categories: [appsec]
tags: [appsec]
---

In the time before improved multi-factor authentication schemes like Authy and Yubikeys, there were security questions. And for some reason, they seem as though they'll never give us up. Even today, some organizations still rely on them, asking users to set questions and answers as a way to validate users out-of-band, in the event of forgetting a password. You might recall services like AOL and AIM using these. But if anything, they're more of a security vulnerability.


Recently, while pentesting a company this week, I was briefly reminded of this concept, being prompted to set questions and answers to the likes of "Where did you grow up?", "What was your first car?", "Who is your favorite musical artist?" While some implementations might rely on more robust security question configurations that employ other variables like texts, email, or actual 2FA before authorizing a password reset, some don't.


Obviously this means sometimes all that may be needed to reset a user's password is to answer a few questions which could potentially be passively gleaned from the internet or social engineering.


Given that we have new generations of technologies and services that enable much safer multiple-factor authentication, it's concerning to see some organizations still using primitive security question questionnaires to authorize password resets. I think we should abandon the practice entirely.