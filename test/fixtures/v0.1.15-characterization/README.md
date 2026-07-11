# v0.1.15 Characterization Index

This directory is a compatibility index, not new runtime evidence. It names the
v0.1.15 surfaces that v0.2 must preserve, migrate, or replace before deletion.
The referenced tests and immutable evidence remain in their authoritative
locations.

`manifest.json` is intentionally small and machine checked. Proof references
name either the signed v0.1.15 commit or current v0.2 authority; mutable HEAD
paths alone are not presented as historical release evidence. Add a surface
only when its proof reference exists and its v0.2 disposition is explicit.
The check fails closed when the signed baseline tag is unavailable; the
authoritative GF check therefore uses a full-history checkout.
