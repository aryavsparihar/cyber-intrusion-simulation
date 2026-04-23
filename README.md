# Cyber Intrusion Detection System (CIDS)

A basic command-line simulation of an intrusion detection system built with C++ and the Standard Template Library (STL). This is a **simple educational project** designed to demonstrate fundamental programming concepts, not a production-ready security tool.

## What This Is

- A learning project focused on C++ STL containers and OOP principles
- A simplified simulation of how basic IDS systems might detect threats
- An interactive CLI program for experimenting with packet processing concepts

## What This Is NOT

- Not a real intrusion detection system
- Not suitable for actual network security
- Not using real network interfaces or packet capture
- Not implementing sophisticated machine learning or detection algorithms

## Features

- **Simulated packet generation** with random IP addresses and protocols
- **Threshold-based detection** (request frequency, packet size, suspicious ports)
- **Blacklist/whitelist management** for IP addresses
- **Sliding time-window analysis** for detecting burst traffic
- **Alert logging** to file and console
- **Traffic statistics** and reporting

## STL Components Demonstrated

- `std::map` - IP address to statistics mapping
- `std::set` - Blacklist and whitelist storage
- `std::vector` - Alert history and sorted data
- `std::queue` - Incoming packet buffer (FIFO)
- `std::deque` - Sliding time window for recent timestamps

## Compilation

```bash
g++ -std=c++11 -o cids cids.cpp
