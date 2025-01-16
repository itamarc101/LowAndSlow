
# **Low-and-Slow HTTP/2 Attack Detection Tool**

## **Description**
Low-and-slow attacks on HTTP/2 are a form of Denial-of-Service (DoS) attacks that exploit the protocol's features to evade detection. These attacks operate by sending minimal amounts of data at a slow rate across multiple connections, making them difficult to identify using traditional traffic monitoring techniques.

We present Low-and-Slow HTTP/2 Attack Detection Tool, a practical and comprehensive approach to detect such attacks in HTTP/2 traffic. Unlike conventional methods, this tool integrates event-sequence learning and delay analysis to identify anomalous behaviors that indicate the presence of slow-rate attacks. The tool operates in three distinct phases:

1. Learning Phase: It processes HTTP/2 traffic to extract event sequences and calculate delays between consecutive events. The learned lookahead pairs and delay thresholds serve as baselines for anomaly detection.
2. Detection Phase: Using the learned event and delay baselines, it evaluates new traffic to identify delay violations and unexpected behaviors indicative of low-and-slow attacks.
3. Mismatch Detection Phase: By analyzing mismatched event sequences, it detects irregularities that deviate from the learned HTTP/2 traffic patterns.
The tool operates seamlessly with tshark for HTTP/2 stream splitting and Scapy for packet inspection, allowing precise detection without requiring modifications to the target infrastructure. It produces clear and actionable logs detailing delay anomalies, mismatched event sequences, and identified attack behaviors. This approach ensures compatibility with real-world traffic analysis pipelines and can be applied to large-scale network monitoring tasks.

Experimental evaluations demonstrate the effectiveness of the tool in detecting low-and-slow attacks, providing network analysts and security teams with a reliable solution for safeguarding HTTP/2-enabled applications and servers.

## **Overview**
This project provides a script to analyze HTTP/2 traffic, detecting **low-and-slow attacks**. It uses **event learning** and **delay analysis** techniques to identify anomalous behaviors in the traffic flow.


## **Features**
- **Learning Phase:** Extracts event sequences and calculates delays between events from captured traffic.
- **Detection Phase:** Identifies anomalies based on delays and mismatches in the learned event sequences.
- **Stream Splitting:** Splits individual HTTP/2 streams from PCAP files for fine-grained analysis.
- **Output Reports:** Generates delay violations, lookahead pair mismatches, and anomaly logs.


### **Modes of Operation**
The script has **3 main phases**:
1. **Learning Phase:**
   - Extracts lookahead pairs and delay statistics.
   - Saves learned data to `Dlookahead.txt` and `Ddelay.txt`.
2. **Detection Phase:**
   - Detects delay violations in new traffic based on learned delays.
3. **Mismatch Detection Phase:**
   - Identifies mismatched event pairs and sequences in the traffic.
  
   ![image](https://github.com/user-attachments/assets/ea4bdd36-cc02-4557-839e-5db5899639df)

   ![detection](https://github.com/user-attachments/assets/fff96efb-3d3d-4790-bcc9-3f88224b8a81)

   ![mismatch](https://github.com/user-attachments/assets/85f7c241-e3c6-431a-89d0-eb7e8766d7f5)


## **Files Generated**
- `Dlookahead.txt`: Contains learned lookahead pairs for event prediction.
- `Ddelay.txt`: Contains maximum delays between consecutive events.
- `DetectMissmatch_<pcap_name>`: Logs mismatched sequences during detection.
- `DelaysDetect_<pcap_name>`: Logs delay anomalies detected in traffic.


## **How It Works**
1. **Stream Splitting:** Extracts individual HTTP/2 streams using `tshark`.
2. **Learning Phase:** Learns event sequences and delays from traffic packets.
3. **Detection Phase:** Compares delays and event mismatches with learned data.
4. **Logging:** Outputs anomalies in the specified report files.
