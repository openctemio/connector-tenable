### Security: SDK and CTIS updated to their current main

- sdk-go moves from v0.32.1-0.20261014164059 to v0.34.1-0.20261018012737 (sdk-go main): the outbound address guard now uses the same deny list as the platform (ctis addrscope), a confined task never dials an address no check has seen, and the job identification reaches every HTTP request of a task.
- ctis moves to its current main (v1.6.1-0.20261016194909); the CTIS report schema stays 1.6.
- No configuration change. Operators rebuild or pull the next image.
