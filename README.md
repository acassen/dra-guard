# DRA Guard: Diameter Routing Agent software

<img width="20%" src="https://www.dra-guard.org/assets/logo.png" align="left"/>
DRA-Guard is a routing software written in C. The main goal of this project is to provide robust and secure extensions to DRA feature (Diameter Routing Agent). DRA are used in mobile networks to route Diameter traffic between mobile network equipments, like at Roaming interconnections. DRA-Guard implements a set of features to manipulate and analyze Diameter payloads via a Plugin framework and a built-in Route-Optimization feature. DRA-Guard relies on Linux Kernel XDP & Qdisc frameworks using eBPF for low-level features like transparent mode operations. Administration and user-level interface are available via a standard VTY terminal interface.

DRA-Guard is free software; you can redistribute it and/or modify it under the terms of the GNU Affero General Public License Version 3.0 as published by the Free Software Foundation.

# What the hell is this ?
DRA-Guard doesn't aim to replace any DRA product, it rather provides a way to extend its behaviours in order to quickly react or add new features. No product can address all needs, mainly because needs for operators are evolving and new ideas are permanently fast moving.

Long story short : DRA-Guard is a SCTP proxy offering access to Diameter payload. For each Diameter payload a plugin callback is invoked. You can then perform any packet analysis/mangling operations you may want and conclude by an action (PASS or DROP). A way to plug into your Diameter data-path and gain control of it.

DRA-Guard is designed for high perf and built around an asynchronous multi-threaded design. Additionnaly it is supporting a transparent mode to simplify its insertion into an existing architecture without the need to reconfigure anything (this is specially useful when you have long list of peers and you need to go fast without wasting time into so called change request).

DRA-Guard is additionnaly implementing a "Route Optimization" framework, a short static example is offered as an example in this OpenSource version, but way more advanced and dynamic routing decisions can be implemented based on multi-metrics.

# Network Architecture
DRA-Guard sits directly at interconnection :
<p align="center"><img src="https://www.dra-guard.org/assets/arch-net.png"></p>

# Software Architecture
If it can be inserted anywhere in your network, it can be useful at interconnection point where you may want to have option to quickly add perf extensions (monitoring, reporting, mitigation, filtering, ...)
<p align="center"><img src="https://www.dra-guard.org/assets/arch-soft.png"></p>

# Local Stack Packet re-circulation
DRA-Guard can operate in transparent mode using state-less operations based on a set of eBPF progs loaded at XDP and Qdisc layers. This design provides fast state-less packet re-circulation into Linux Kernel stack to benefit widely used SCTP stack:
<p align="center"><img src="https://www.dra-guard.org/assets/local-statck-recirculation.png"></p>

