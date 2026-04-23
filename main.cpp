/*
============================================================================
    CYBER INTRUSION DETECTION SYSTEM (CIDS)
    ----------------------------------------------------------------
    A simulation-based cybersecurity application built using C++
    and the Standard Template Library (STL).
    ----------------------------------------------------------------
    PURPOSE:
    This program simulates how real-world Intrusion Detection Systems
    (IDS) monitor network traffic, detect suspicious behavior such as
    DDoS or brute-force attacks, and automatically block malicious
    IP addresses.
    ----------------------------------------------------------------
    CORE CONCEPTS DEMONSTRATED:
    1. STL Containers (map, set, vector, queue, deque)
    2. Object-Oriented Programming (Classes, Encapsulation)
    3. Real-time data simulation
    4. Threshold-based anomaly detection
    5. Sliding time-window analysis
    6. File-based logging of alerts
============================================================================
*/

#include <iostream>
#include <string>
#include <vector>
#include <map>       // For mapping IPs to request counts
#include <set>       // For storing blacklisted IPs (unique entries)
#include <queue>     // For simulating incoming packet queue (FIFO)
#include <deque>     // For sliding time-window analysis
#include <ctime>     // For timestamps
#include <cstdlib>   // For random number generation
#include <fstream>   // For logging alerts to a file
#include <iomanip>   // For formatted output
#include <algorithm> // For sorting operations
using namespace std;

// ========================================================================
// STRUCTURE: Packet
// ------------------------------------------------------------------------
// Represents a single network packet traveling through the network.
// Each packet carries metadata needed for intrusion detection analysis.
// ========================================================================
struct Packet
{
    string sourceIP;  // The IP address that sent the packet
    string destIP;    // The destination IP (target server)
    time_t timestamp; // When the packet arrived (Unix time)
    int size;         // Size of the packet in bytes
    string protocol;  // Communication protocol (TCP/UDP/ICMP)
    int port;         // Destination port number (e.g., 80, 443)
};

// ========================================================================
// STRUCTURE: IPStats
// ------------------------------------------------------------------------
// Keeps detailed statistics for each IP address seen by the system.
// Useful for traffic analysis and generating reports.
// ========================================================================
struct IPStats
{
    int totalRequests = 0;     // Total packets sent
    int totalBytes = 0;        // Total data transmitted
    time_t firstSeen = 0;      // When IP was first observed
    time_t lastSeen = 0;       // Most recent packet time
    deque<time_t> recentTimes; // Recent packet timestamps (for window check)
};

// ========================================================================
// CLASS: IntrusionDetectionSystem
// ------------------------------------------------------------------------
// The main engine that processes packets, analyzes traffic, detects
// anomalies, and manages the blacklist and alert system.
// ========================================================================
class IntrusionDetectionSystem
{
private:
    // STL map: stores statistics for each observed IP address
    // key = IP, value = IPStats object
    map<string, IPStats> ipStats;

    // STL set: stores the blacklist of blocked IPs (no duplicates allowed)
    set<string> blacklist;

    // STL set: stores trusted/whitelisted IPs (never blocked)
    set<string> whitelist;

    // STL vector: maintains history of all generated security alerts
    vector<string> alertLog;

    // STL queue: simulates a buffer of incoming network packets (FIFO)
    queue<Packet> packetQueue;

    // Detection Parameters (tunable thresholds)
    const int REQUEST_THRESHOLD = 5;    // Max requests before flagging
    const int TIME_WINDOW = 10;         // Sliding window size (seconds)
    const int LARGE_PACKET_SIZE = 1500; // Suspicious packet size (bytes)

    // Counters for summary report
    int totalPacketsProcessed = 0;
    int totalPacketsBlocked = 0;
    int totalAlerts = 0;

public:
    // ----------------------------------------------------------------
    // CONSTRUCTOR
    // Initializes the system and adds some default trusted IPs.
    // ----------------------------------------------------------------
    IntrusionDetectionSystem()
    {
        // Add some default safe IPs that must never be blocked
        whitelist.insert("127.0.0.1");   // Localhost
        whitelist.insert("192.168.1.1"); // Gateway
        cout << "[SYSTEM] IDS Initialized. Whitelist and monitors ready.\n";
    }

    // ----------------------------------------------------------------
    // FUNCTION: addPacket
    // Adds an incoming packet to the processing queue.
    // Simulates a network interface receiving traffic.
    // ----------------------------------------------------------------
    void addPacket(Packet p)
    {
        packetQueue.push(p);
    }

    // ----------------------------------------------------------------
    // FUNCTION: isWithinTimeWindow
    // Checks how many packets from an IP fall inside the sliding
    // time window. This helps detect short-burst attacks like DDoS.
    // ----------------------------------------------------------------
    int countRequestsInWindow(const string &ip, time_t currentTime)
    {
        deque<time_t> &times = ipStats[ip].recentTimes;

        // Remove outdated timestamps (older than the time window)
        while (!times.empty() && (currentTime - times.front()) > TIME_WINDOW)
        {
            times.pop_front();
        }
        return times.size();
    }

    // ----------------------------------------------------------------
    // FUNCTION: processPackets
    // Processes every packet currently in the queue, updates statistics,
    // and applies all detection rules.
    // ----------------------------------------------------------------
    void processPackets()
    {
        cout << "\n=========== Processing Incoming Packets ===========\n";

        if (packetQueue.empty())
        {
            cout << "[INFO] No packets to process.\n";
            return;
        }

        // Loop through all packets in the queue
        while (!packetQueue.empty())
        {
            Packet p = packetQueue.front(); // Fetch front packet
            packetQueue.pop();              // Remove it from queue
            totalPacketsProcessed++;

            // STEP 1: Check if the IP is in the whitelist (safe IPs)
            if (whitelist.find(p.sourceIP) != whitelist.end())
            {
                cout << "[SAFE] Packet from trusted IP " << p.sourceIP
                     << " allowed automatically.\n";
                continue;
            }

            // STEP 2: Check if the IP is already blacklisted
            if (blacklist.find(p.sourceIP) != blacklist.end())
            {
                cout << "[BLOCKED] Packet from " << p.sourceIP
                     << " rejected (IP is blacklisted).\n";
                totalPacketsBlocked++;
                continue;
            }

            // STEP 3: Update IP statistics
            IPStats &stats = ipStats[p.sourceIP];
            if (stats.totalRequests == 0)
                stats.firstSeen = p.timestamp;
            stats.lastSeen = p.timestamp;
            stats.totalRequests++;
            stats.totalBytes += p.size;
            stats.recentTimes.push_back(p.timestamp);

            // STEP 4: Count recent requests using the sliding time window
            int recentCount = countRequestsInWindow(p.sourceIP, p.timestamp);

            // Display packet information
            cout << "[INFO] " << p.sourceIP << " -> " << p.destIP
                 << " | " << p.protocol << " | Port: " << p.port
                 << " | Size: " << p.size << "B"
                 << " | Recent: " << recentCount << "\n";

            // STEP 5: Apply detection rules

            // Rule 1: Too many requests in a short time (DDoS pattern)
            if (recentCount > REQUEST_THRESHOLD)
            {
                generateAlert(p.sourceIP,
                              "High request frequency detected (possible DDoS)");
                addToBlacklist(p.sourceIP);
            }

            // Rule 2: Unusually large packet size (possible payload attack)
            else if (p.size > LARGE_PACKET_SIZE)
            {
                generateAlert(p.sourceIP,
                              "Oversized packet detected (possible buffer overflow)");
            }

            // Rule 3: Suspicious ports (commonly attacked)
            else if (p.port == 23 || p.port == 3389)
            {
                generateAlert(p.sourceIP,
                              "Access attempt on sensitive port " + to_string(p.port));
            }
        }

        cout << "===================================================\n";
    }

    // ----------------------------------------------------------------
    // FUNCTION: generateAlert
    // Creates a formatted alert message, stores it in memory,
    // and writes it to a log file for record keeping.
    // ----------------------------------------------------------------
    void generateAlert(const string &ip, const string &reason)
    {
        time_t now = time(0);
        string timeStr = ctime(&now);
        timeStr.pop_back(); // Remove trailing newline from ctime

        string alert = "[ALERT] " + timeStr + " | IP: " + ip + " | " + reason;
        alertLog.push_back(alert);
        totalAlerts++;

        cout << ">>> " << alert << " <<<\n";

        // Save alert to a log file for persistence
        ofstream logFile("cids_alerts.log", ios::app);
        if (logFile.is_open())
        {
            logFile << alert << "\n";
            logFile.close();
        }
    }

    // ----------------------------------------------------------------
    // FUNCTION: addToBlacklist
    // Adds a suspicious IP to the blacklist, blocking future packets.
    // ----------------------------------------------------------------
    void addToBlacklist(const string &ip)
    {
        if (blacklist.find(ip) == blacklist.end())
        {
            blacklist.insert(ip);
            cout << "[ACTION] IP " << ip << " added to blacklist.\n";
        }
    }

    // ----------------------------------------------------------------
    // FUNCTION: removeFromBlacklist
    // Lets the admin unblock an IP manually.
    // ----------------------------------------------------------------
    void removeFromBlacklist(const string &ip)
    {
        if (blacklist.erase(ip) > 0)
        {
            cout << "[ACTION] IP " << ip << " removed from blacklist.\n";
        }
        else
        {
            cout << "[INFO] IP " << ip << " was not in the blacklist.\n";
        }
    }

    // ----------------------------------------------------------------
    // FUNCTION: addToWhitelist
    // Adds an IP to the trusted list so it is never blocked.
    // ----------------------------------------------------------------
    void addToWhitelist(const string &ip)
    {
        whitelist.insert(ip);
        cout << "[ACTION] IP " << ip << " added to whitelist.\n";
    }

    // ----------------------------------------------------------------
    // FUNCTION: showBlacklist
    // Displays all currently blocked IPs.
    // ----------------------------------------------------------------
    void showBlacklist()
    {
        cout << "\n----------- Blacklisted IP Addresses -----------\n";
        if (blacklist.empty())
        {
            cout << "No IPs are currently blacklisted.\n";
            return;
        }
        int count = 1;
        for (const string &ip : blacklist)
        {
            cout << count++ << ". " << ip << "\n";
        }
        cout << "Total blocked: " << blacklist.size() << "\n";
    }

    // ----------------------------------------------------------------
    // FUNCTION: showWhitelist
    // Displays all trusted (never-blocked) IPs.
    // ----------------------------------------------------------------
    void showWhitelist()
    {
        cout << "\n----------- Whitelisted IP Addresses -----------\n";
        if (whitelist.empty())
        {
            cout << "Whitelist is empty.\n";
            return;
        }
        for (const string &ip : whitelist)
        {
            cout << " - " << ip << "\n";
        }
    }

    // ----------------------------------------------------------------
    // FUNCTION: showAlerts
    // Displays all alerts generated during this session.
    // ----------------------------------------------------------------
    void showAlerts()
    {
        cout << "\n----------- Security Alert Log -----------\n";
        if (alertLog.empty())
        {
            cout << "No alerts have been generated yet.\n";
            return;
        }
        for (const string &alert : alertLog)
        {
            cout << alert << "\n";
        }
        cout << "Total alerts: " << alertLog.size() << "\n";
    }

    // ----------------------------------------------------------------
    // FUNCTION: showTrafficSummary
    // Shows a formatted table of traffic statistics per IP.
    // ----------------------------------------------------------------
    void showTrafficSummary()
    {
        cout << "\n----------- Traffic Summary Report -----------\n";
        if (ipStats.empty())
        {
            cout << "No network traffic recorded yet.\n";
            return;
        }

        // Print table header
        cout << left << setw(18) << "IP Address"
             << setw(12) << "Requests"
             << setw(14) << "Total Bytes"
             << setw(12) << "Status" << "\n";
        cout << string(56, '-') << "\n";

        // Print each IP's statistics
        for (auto &pair : ipStats)
        {
            string status = "Normal";
            if (blacklist.count(pair.first))
                status = "BLOCKED";
            else if (whitelist.count(pair.first))
                status = "TRUSTED";

            cout << left << setw(18) << pair.first
                 << setw(12) << pair.second.totalRequests
                 << setw(14) << pair.second.totalBytes
                 << setw(12) << status << "\n";
        }
    }

    // ----------------------------------------------------------------
    // FUNCTION: showTopAttackers
    // Shows the top N IPs with the most requests (attack suspects).
    // ----------------------------------------------------------------
    void showTopAttackers(int topN = 3)
    {
        cout << "\n----------- Top " << topN << " Most Active IPs -----------\n";
        if (ipStats.empty())
        {
            cout << "No traffic recorded.\n";
            return;
        }

        // Copy map data into a vector for sorting
        vector<pair<string, int>> sortedIPs;
        for (auto &p : ipStats)
        {
            sortedIPs.push_back({p.first, p.second.totalRequests});
        }

        // Sort in descending order by request count
        sort(sortedIPs.begin(), sortedIPs.end(),
             [](const pair<string, int> &a, const pair<string, int> &b)
             {
                 return a.second > b.second;
             });

        // Display top N
        int limit = min(topN, (int)sortedIPs.size());
        for (int i = 0; i < limit; i++)
        {
            cout << (i + 1) << ". " << sortedIPs[i].first
                 << " -> " << sortedIPs[i].second << " requests\n";
        }
    }

    // ----------------------------------------------------------------
    // FUNCTION: showSystemStats
    // Displays an overall dashboard of system activity.
    // ----------------------------------------------------------------
    void showSystemStats()
    {
        cout << "\n=========== System Dashboard ===========\n";
        cout << "Total Packets Processed : " << totalPacketsProcessed << "\n";
        cout << "Total Packets Blocked   : " << totalPacketsBlocked << "\n";
        cout << "Total Alerts Generated  : " << totalAlerts << "\n";
        cout << "Unique IPs Observed     : " << ipStats.size() << "\n";
        cout << "Blacklisted IPs         : " << blacklist.size() << "\n";
        cout << "Whitelisted IPs         : " << whitelist.size() << "\n";
        cout << "Packets in Queue        : " << packetQueue.size() << "\n";
        cout << "========================================\n";
    }

    // ----------------------------------------------------------------
    // FUNCTION: clearAlerts
    // Clears the alert history.
    // ----------------------------------------------------------------
    void clearAlerts()
    {
        alertLog.clear();
        cout << "[ACTION] All alerts cleared from memory.\n";
    }
};

// ========================================================================
// FUNCTION: generateRandomPacket
// ------------------------------------------------------------------------
// Simulates generation of a random packet. Some IPs are repeated to
// mimic attack-like behavior (so the detection system can catch them).
// ========================================================================
Packet generateRandomPacket()
{
    // Pool of sample IP addresses (some repeat on purpose)
    vector<string> ipPool = {
        "192.168.1.10", // Normal user
        "192.168.1.20", // Normal user
        "10.0.0.5",     // Normal user
        "172.16.0.3",   // Normal user
        "203.0.113.50", // Attacker (repeated below)
        "203.0.113.50",
        "203.0.113.50",
        "203.0.113.50",
        "203.0.113.50",
        "203.0.113.50",  // Will trigger threshold
        "198.51.100.77", // Another suspicious IP
        "198.51.100.77",
        "127.0.0.1" // Whitelisted localhost
    };

    // Pool of protocols used in real networks
    vector<string> protocols = {"TCP", "UDP", "ICMP"};

    // Commonly targeted port numbers (some are sensitive)
    vector<int> ports = {80, 443, 22, 23, 3389, 8080, 21};

    Packet p;
    p.sourceIP = ipPool[rand() % ipPool.size()];
    p.destIP = "192.168.1.1"; // Simulated server IP
    p.timestamp = time(0);
    p.size = 64 + rand() % 2000; // 64 - 2063 bytes
    p.protocol = protocols[rand() % protocols.size()];
    p.port = ports[rand() % ports.size()];
    return p;
}

// ========================================================================
// FUNCTION: displayMenu
// Shows the main menu options to the user.
// ========================================================================
void displayMenu()
{
    cout << "\n================ CIDS MENU ================\n";
    cout << " 1. Simulate Incoming Packets\n";
    cout << " 2. Process Packets & Detect Threats\n";
    cout << " 3. Show Traffic Summary\n";
    cout << " 4. Show Alerts\n";
    cout << " 5. Show Blacklisted IPs\n";
    cout << " 6. Show Whitelisted IPs\n";
    cout << " 7. Show Top Attackers\n";
    cout << " 8. Add IP to Whitelist\n";
    cout << " 9. Remove IP from Blacklist\n";
    cout << "10. Show System Dashboard\n";
    cout << "11. Clear Alert Log\n";
    cout << "12. Exit\n";
    cout << "===========================================\n";
    cout << "Enter your choice: ";
}

// ========================================================================
// MAIN FUNCTION
// ------------------------------------------------------------------------
// Entry point of the program. Provides an interactive menu so the user
// can simulate traffic, detect threats, and view reports.
// ========================================================================
int main()
{
    srand(time(0));               // Seed random generator
    IntrusionDetectionSystem ids; // Create IDS instance
    int choice;
    string ip;

    // Welcome banner
    cout << "\n*****************************************************\n";
    cout << "*     CYBER INTRUSION DETECTION SYSTEM (CIDS)       *\n";
    cout << "*       Real-Time Network Threat Simulator          *\n";
    cout << "*****************************************************\n";

    // Main interactive loop
    do
    {
        displayMenu();
        cin >> choice;

        switch (choice)
        {
        case 1:
        {
            // Simulate multiple incoming packets
            int n;
            cout << "Enter number of packets to simulate: ";
            cin >> n;
            for (int i = 0; i < n; i++)
            {
                Packet p = generateRandomPacket();
                ids.addPacket(p);
            }
            cout << "[OK] " << n << " packets added to the queue.\n";
            break;
        }
        case 2:
            // Analyze all queued packets
            ids.processPackets();
            break;
        case 3:
            ids.showTrafficSummary();
            break;
        case 4:
            ids.showAlerts();
            break;
        case 5:
            ids.showBlacklist();
            break;
        case 6:
            ids.showWhitelist();
            break;
        case 7:
        {
            int n;
            cout << "Enter how many top IPs to display: ";
            cin >> n;
            ids.showTopAttackers(n);
            break;
        }
        case 8:
            cout << "Enter IP to whitelist: ";
            cin >> ip;
            ids.addToWhitelist(ip);
            break;
        case 9:
            cout << "Enter IP to remove from blacklist: ";
            cin >> ip;
            ids.removeFromBlacklist(ip);
            break;
        case 10:
            ids.showSystemStats();
            break;
        case 11:
            ids.clearAlerts();
            break;
        case 12:
            cout << "\n[SYSTEM] Shutting down CIDS. Stay Secure! 🔐\n";
            break;
        default:
            cout << "[ERROR] Invalid choice. Please try again.\n";
        }

    } while (choice != 12);

    return 0;
}