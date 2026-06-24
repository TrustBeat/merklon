# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Email **radim.dejmek@trustbeat.eu** with:

- a description of the issue and its impact,
- steps to reproduce (a proof of concept if possible),
- affected version(s) / commit.

You will receive an acknowledgement within **5 business days**. We aim to provide an
initial assessment within **10 business days** and will keep you informed about the
fix and disclosure timeline.

We follow **coordinated disclosure**: please give us a reasonable window to release a
fix before any public disclosure. We are happy to credit reporters who wish to be named.

## Scope

This project is cryptographic infrastructure. Issues of particular interest include,
but are not limited to:

- incorrect inclusion or consistency proof verification,
- any way to make the log accept a non-append-only mutation,
- checkpoint/signature forgery or confusion,
- split-view / equivocation that escapes witness detection,
- proof-bundle verification bypass.

## Supported versions

The project is pre-1.0. Only the latest `main` is supported until a stable release line
is established.
