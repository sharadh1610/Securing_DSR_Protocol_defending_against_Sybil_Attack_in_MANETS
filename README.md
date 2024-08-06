**Sybil Attack Prevention in DSR Protocol for MANETs**
=========================

This project offers a robust solution to counter Sybil attacks in Mobile Ad Hoc Networks (MANETs) using the Dynamic Source Routing (DSR) protocol. Our approach enhances route caching to ensure network reliability and security.

**Overview**
=========================

**What Are MANETs?**
Mobile Ad Hoc Networks (MANETs) are decentralized networks where nodes communicate directly without fixed infrastructure. These networks are ideal for scenarios such as military operations or disaster relief where traditional network infrastructure is unavailable. Nodes in a MANET can move freely, creating dynamic and self-organizing communication paths.

**Dynamic Source Routing (DSR) Protocol**
The DSR protocol enables efficient routing in MANETs by using route caching. It allows nodes to store and reuse discovered routes, reducing overhead and speeding up communication. However, DSR can be vulnerable to various attacks, including the Sybil attack.

**What Is a Sybil Attack?**
A Sybil attack involves a single malicious node pretending to be multiple fake nodes. This deception can disrupt routing, cause packet drops, and degrade network performance. Protecting against this attack is crucial for maintaining a reliable network.

**Our Solution**
Innovative Sybil Attack Prevention
Our project introduces a novel method to enhance the DSR protocol’s route caching mechanism to prevent Sybil attacks. Here’s how it works:

Detection: Identify Sybil nodes during route establishment.
Verification: Before adding a route to the cache, check for Sybil node identities.
Integration: Integrate this verification into the caching process, ensuring minimal impact on performance.
Why It Matters
Our solution significantly reduces packet drops and improves network reliability by filtering out routes involving Sybil nodes. Simulations using NS-2 show a substantial reduction in packet loss with minimal false positives, enhancing the overall performance of MANETs.

Quick Start
Clone the Repository:

bash
Copy code
git clone https://github.com/yourusername/your-repository.git
Navigate to the Project Directory:

bash
Copy code
cd your-repository
Build and Run:
Follow the instructions in INSTALL.md to set up your environment and dependencies.

Run Simulations:
Configure your simulation parameters in config-file and execute:

bash
Copy code
./run_simulation.sh
How It Works
Route Caching and Sybil Attack Prevention
Our solution enhances the route caching process in the DSR protocol by:

Detecting Sybil Nodes: Identifying malicious nodes during route setup.
Filtering Routes: Checking for Sybil node identities before caching routes.
Maintaining Performance: Ensuring minimal disruption to the existing caching process.
This approach prevents fake nodes from influencing routing paths, thus protecting the network from packet drops and performance degradation.
