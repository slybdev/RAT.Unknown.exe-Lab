# RAT.unknown.exe Malware Analysis

## Objective  
The goal of this project was to analyze a Remote Access Trojan (RAT) sample (`RAT.unknown.exe`) in a controlled home lab environment using FLARE VM and REMnux. The objective was to investigate how the malware behaves, communicates, establishes persistence, and allows remote access.

### Skills Learned
- Performing static analysis using FLOSS and VirusTotal
- Setting up INetSim and Wireshark for C2 traffic emulation
- Detecting host-based indicators with Procmon and TCPView
- Capturing and decoding base64-encoded command & control messages
- Identifying persistence mechanisms via file path monitoring
- Establishing remote shell access via Ncat

### Tools Used
- FLARE VM (Windows Analysis)
- REMnux (Network Emulation & Packet Capture)
- VirusTotal
- FLOSS (FireEye Labs Obfuscated String Solver)
- INetSim (Fake Internet Services)
- Wireshark (Packet Analysis)
- Procmon (Process Monitor)
- TCPView
- Ncat

## Steps

### 1. Static Analysis
- Uploaded the malware hash to VirusTotal and confirmed detection by multiple engines.  
- Used **FLOSS** to extract strings; discovered:
  - Suspicious domains like `http://serv1.ec2-102-95-13-2-ubuntu.local`
  - Payload links such as `https://msdcorelib.exe`
  - File names and indicators of persistence behavior
    
![Screenshot 3](https://github.com/user-attachments/assets/5b8160a8-0e55-403e-9c59-6bd7e2c4eb7b)
![Screenshot 4](https://github.com/user-attachments/assets/b3755657-eecd-4603-9b41-aa90aa465137)
![Screenshot 5](https://github.com/user-attachments/assets/9d005b67-744e-4113-8a87-48ddbcda36c0)
![Screenshot 6](https://github.com/user-attachments/assets/df05f405-477f-4f9b-8470-ee67118ab4f1)

### 2. Dynamic Analysis (FLARE VM + REMnux)
- Ran the malware on FLARE VM and got a pop-up:  
  **"No Soup Found"**

- Suspecting C2 interaction, I:
  - Set REMnux’s DNS as the host machine DNS
  - Ran **INetSim** to emulate fake internet services
  - Started Wireshark to capture traffic

- On re-running the malware:
  - It attempted to reach `http://serv1.ec2-102-95-13-2-ubuntu.local`
  - The pop-up no longer appeared
  - It downloaded a secondary file from `https://msdcorelib.exe`
 
  ![Screenshot 10](https://github.com/user-attachments/assets/52144d7c-da7c-4220-bbb1-6662309b6251)
![Screenshot 1](https://github.com/user-attachments/assets/9f50e4eb-1286-4479-9d2f-7675b66d435c)
![Screenshot 22](https://github.com/user-attachments/assets/ab293f50-752f-4f55-91c0-37eb56050828)
![Screenshot 23](https://github.com/user-attachments/assets/fb615128-5a2f-401b-98a9-3c8f238f4c14)
![Screenshot 24](https://github.com/user-attachments/assets/3196904a-659a-4b0b-881a-256a9c750968)

![Screenshot 15](https://github.com/user-attachments/assets/1009b1e9-5297-46b1-9fc0-82e4ba28ca06)

### 3. Host-Based Behavioral Analysis
- Launched **Procmon** and filtered events by the malware's process name
  - Found the malware dropped a file to the `C:\Users\Public\Startup\` folder
  - Classic Windows persistence tactic

- Used **TCPView** to inspect network activity
  - Found the malware listening on **port 5555**

![Screenshot 21](https://github.com/user-attachments/assets/40763b94-d5c5-4ac8-81c4-f8fbf9c70d59)

![Screenshot 25](https://github.com/user-attachments/assets/4aefe01e-4f4e-47cf-9b9b-ae2e75d6d2b1)
![Screenshot 26](https://github.com/user-attachments/assets/084ec00c-c482-418d-a638-51bf84836468)
![Screenshot 27](https://github.com/user-attachments/assets/3a56f451-a2fe-418e-aaa0-a445572298a7)

### 4. Post-Exploitation
- Connected to the open socket using:  
  `ncat -nv 10.0.0.4 5555`

- Sent encoded system commands like `ipconfig` and received Base64-encoded results
- Decoded response showed system IP configuration
- Got a **Base64-encoded response**:
---


  ![Screenshot 29](https://github.com/user-attachments/assets/3696b9e3-3c5b-4311-8b7a-93c9f7564f08)
![Screenshot 30](https://github.com/user-attachments/assets/11605554-6db1-45fb-b089-0afd7451c515)

![Screenshot 31](https://github.com/user-attachments/assets/cca7a02a-e831-4de7-979b-b138374d3a48)

## Summary  
This project provided hands-on experience in dissecting a real-world RAT, understanding how it hides, communicates with C2 servers, achieves persistence, and enables remote access. It also strengthened my analysis workflow using both host-based and network-based tools in a home lab setup.

📎 **LinkedIn write-up**: []  


---

## Next Steps (Future Improvements)
- Reverse engineering the downloaded payload with Ghidra or IDA
- Automating detection rules using Sigma/YARA
- Writing custom Suricata rules based on C2 traffic

## Disclaimer
This analysis was conducted in a secure, isolated lab environment. The sample and tools used are for educational and research purposes only.

