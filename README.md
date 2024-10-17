# DRA Guard: Diameter Routing Agent software

<img width="20%" src="https://www.dra-guard.org/assets/logo.png" align="left"/>

DRA-Guard is a routing software written in C. The main goal of this project is to provide robust and secure extensions to DRA feature (Diameter Routing Agent). DRA are used in mobile networks in order to redirect users terminals to their HPLMN in Roaming situations. DRA-Guard implements a set of features to manipulate and analyze Diameter payloads via a Plugin framework and a built-in Route-Optimization feature. DRA-Guard relies on Linux Kernel XDP & Qdisc frameworks using eBPF for low-level features like transparent mode operations. Administration and user-level interface are available via a standard VTY terminal interface.

DRA-Guard is free software; you can redistribute it and/or modify it under the terms of the GNU Affero General Public License Version 3.0 as published by the Free Software Foundation.


# Network Architecture

DRA-Guard sits directly at interconnection :
<p align="center"><img src="https://www.dra-guard.org/assets/arch-net.png"></p>

# Software Architecture

DRA-Guard is articulated around following components :
<p align="center"><img src="https://www.dra-guard.org/assets/arch-soft.png"></p>

# Local Stack Packet re-circulation

DRA-Guard can operate in transparent mode using state-less operations based on a set of eBPF progs loaded at XDP and Qdisc layers. This design provides fast state-less packet re-circulation into Linux Kernel stack to benefit largely used SCTP stack:
<p align="center"><img src="https://www.dra-guard.org/assets/local-statck-recirculation.png"></p>

