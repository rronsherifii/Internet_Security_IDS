## Internet Security - Simple IDS


### Overview - Scanning
In this project we have created a simple host intrustion detection system, which listens for attacks like ICMP Flood, HTTP Flood and SYN Flood and prints out if there is a possible attack, 
together with the timestamp, attacker IP address and interface. The library used for sniffing packets is **pyshark** and the scanning part is utilized by using **threading** library, for parallell 
listening of attacks.

The scanning part uses an *SQLITE* database for saving the attack information, which it fetches continuously to show on the GUI, which is made using the **tkinter** library. 

### Overview - Attack
To test the application, we send malicious packets to the interface of the IDS (supposedly our laptop) using the python attack scrips made. The ICMP Flood attack uses the **ping3** library for continuosly sending
ICMP packets, but even *PING apps* installed on our phones can do the job. As per the SYN flood the *nping* command is used whereas for the HTTP Flood we send continious HTTP Requests to our web server.
The web server is run on the Scanner side, using the command *python -m http.server*.

### Installation
1. **Clone repository**
  Firstly clone the repository using :
  > git clone https://github.com/rronsherifii/Internet_Security_IDS.git
  After doing so, move into the Scanning folder with:
  > cd Scanning
  When we change directory, we run the main GUI which listens for attacks with:
  >  python table.py      
2. **Send attacks**
  To send the attacks move into the *Attacks* directory using **cd**. After that go into the terminal and type **python *attack-type.py* ** 
