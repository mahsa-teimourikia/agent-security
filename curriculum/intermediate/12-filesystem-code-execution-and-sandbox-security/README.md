# 12 — Filesystem, Code-Execution, and Sandbox Security

Threat-model untrusted code under a plain process, restricted user, rootless
container, and stronger gVisor/VM/Firecracker-style isolation. Safely simulate
filesystem escape, environment-secret read, process spawn, CPU/memory pressure,
and workspace write. Enforce filesystem, process, network, time, memory, and
identity limits; measure denied escape and bounded resources. Containers alone
are not a complete hostile-code boundary.
