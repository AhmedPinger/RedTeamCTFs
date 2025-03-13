### **OWASP Top 10 for LLM**

1. **A01: Prompt Injection** 
2. **A02: Model Hijacking**
3. **A03: Excessive Permissions**
4. **A04: Insecure Data Handling**
5. **A05: Remote Code Execution**
6. **A09: Data Exfiltration**

###  **MITRE ATT&CK TTPs**

##### **Initial Access**
   - **T1203** - Exploitation for Client Execution (AI chatbot vulnerability)
##### **Execution**
   - **T1059.001** - Command and Scripting Interpreter (Reverse shell on chatbot server)
##### **Persistence**
   - **T1078** - Valid Accounts (Jump server compromise)
   - **T1078.001** - Valid Accounts: Cloud Services (AWS IAM role access)
##### **Collection**
   - **T1530** - Data from Cloud Storage Object (Accessing S3 bucket)
##### **Discovery**
   - **T1087.002** - Account Discovery: Active Directory (BloodHound data exploitation)
### 6. **Lateral Movement**
   - **T1078.001** - Valid Accounts (Lateral movement with admin credentials)
### 7. **Privilege Escalation**
   - **T1055-6** - Process Injection (Process injection during lateral movement)
   - **T1484.001** - Domain Policy Modification (Domain controller compromise)

---

### **Detailed Attack Scenario**

This scenario describes a complex attack chain where an AI chatbot vulnerability leads to a severe breach of an organization’s internal network, using cloud infrastructure (AWS) and on-premise resources (like jump servers and Active Directory).

1. **AI Chatbot Vulnerability (Initial Access)**  
   The web application of chatbot run on some weird port on the application as a frontend and connects with the backend of chatbot server, An attacker managed to get that port number, then attacker is presented with the chatbot application, then attacker exploits a vulnerability in the company’s AI compliance chatbot through a **prompt injection** attack, retrieving sensitive information like non-compliant passwords from audit and pentest report.  
   - **MITRE T1203 - Exploitation for Client Execution**  
   - **OWASP A01: Prompt Injection**

2. **Reverse Shell on Chatbot Server (Execution)**  
   The attacker further exploits a vulnerability in the chatbot to execute commands and obtain a **reverse shell** on the chatbot server, which serves as the only point of access to a jump server within the organization’s DMZ.  
   - **MITRE T1059.001 - Command and Scripting Interpreter**  
   - **OWASP A05: Remote Code Execution**

3. **Jump Server Compromise (Persistence)**  
   Using credentials retrieved from the chatbot, the attacker logs into the jump server. The jump server has an attached IAM role, and by using the **AWS CLI**, the attacker extracts AWS metadata containing **access and secret keys**, gaining cloud permissions.  
   - **MITRE T1078 - Valid Accounts**  
   - **MITRE T1078.001 - Valid Accounts: Cloud Services**  
   - **OWASP A03: Excessive Permissions**

4. **Accessing S3 Bucket (Collection)**  
   With the stolen AWS keys, the attacker accesses an **S3 bucket** containing sensitive compliance data, including **BloodHound** files that map Active Directory (AD) relationships.  
   - **MITRE T1530 - Data from Cloud Storage Object**  
   - **OWASP A04: Insecure Data Handling**

5. **BloodHound Data Exploitation (Discovery)**  
   The attacker uses **BloodHound** to analyze AD and identify exploitable **ACLs** (Access Control Lists). In this process, they find credentials for a local admin account stored in a description field.  
   - **MITRE T1087.002 - Account Discovery: Active Directory**

6. **Lateral Movement (Lateral Movement)**  
   With local admin credentials, the attacker compromises a machine using **process injection** and retrieves machine account information. The attacker then exploits an **ACL** vulnerability to perform a **Computer Account Write Permissions** attack, adding a new computer to the AD and configuring **Resource-Based Constrained Delegation (RBCD)**.  
   - **MITRE T1078.001 - Valid Accounts**  
   - **MITRE T1055 - Process Injection**

7. **Domain Controller Compromise (Privilege Escalation)**  
   With RBCD enabled, the attacker gains control of the **Domain Controller**, securing administrative access over the entire AD environment.  
   - **MITRE T1484.001 - Domain Policy Modification**  
   - **OWASP A09: Data Exfiltration**