import { Vulnerability } from '../types/vulnerability';

export const vulnerabilityData: Vulnerability[] = [
  {
    cveID: "CVE-2024-2552",
    name: "PAN-OS: Arbitrary File Delete Vulnerability in the Command Line Interface (CLI)",
    description: "A command injection vulnerability in Palo Alto Networks PAN-OS software enables an authenticated administrator to bypass system restrictions in the management plane and delete files on the firewall.",
    cwe: "CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"
  },
  {
    cveID: "CVE-2024-2431",
    name: "GlobalProtect App: Local User Can Disable GlobalProtect",
    description: "An issue in the Palo Alto Networks GlobalProtect app enables a non-privileged user to disable the GlobalProtect app in configurations that allow a user to disable GlobalProtect with a passcode.",
    cwe: "CWE-269 Improper Privilege Management"
  },
  {
    cveID: "CVE-2024-2432",
    name: "GlobalProtect App: Local Privilege Escalation (PE) Vulnerability",
    description: "A privilege escalation (PE) vulnerability in the Palo Alto Networks GlobalProtect app on Windows devices enables a local user to execute programs with elevated privileges. However, execution requires that the local user is able to successfully exploit a race condition.",
    cwe: "CWE-269 Improper Privilege Management"
  },
  {
    cveID: "CVE-2024-2433",
    name: "PAN-OS: Improper Privilege Management Vulnerability in Panorama Software Leads to Availability Loss",
    description: "An improper authorization vulnerability in Palo Alto Networks Panorama software enables an authenticated read-only administrator to upload files using the web interface and completely fill one of the disk partitions with those uploaded files, which prevents the ability to log into the web interface or to download PAN-OS, WildFire, and content images. \n\n\n\nThis issue affects only the web interface of the management plane; the dataplane is unaffected.\n",
    cwe: "CWE-269 Improper Privilege Management"
  },
  {
    cveID: "CVE-2024-2551",
    name: "PAN-OS: Firewall Denial of Service (DoS) Using a Specially Crafted Packet",
    description: "A null pointer dereference vulnerability in Palo Alto Networks PAN-OS software enables an unauthenticated attacker to stop a core system service on the firewall by sending a crafted packet through the data plane that causes a denial of service (DoS) condition. Repeated attempts to trigger this condition result in the firewall entering maintenance mode.",
    cwe: "CWE-476 NULL Pointer Dereference"
  },
  {
    cveID: "CVE-2024-2550",
    name: "PAN-OS: Firewall Denial of Service (DoS) in GlobalProtect Gateway Using a Specially Crafted Packet",
    description: "A null pointer dereference vulnerability in the GlobalProtect gateway in Palo Alto Networks PAN-OS software enables an unauthenticated attacker to stop the GlobalProtect service on the firewall by sending a specially crafted packet that causes a denial of service (DoS) condition. Repeated attempts to trigger this condition result in the firewall entering maintenance mode.",
    cwe: "CWE-476 NULL Pointer Dereference"
  },
  {
    cveID: "CVE-2024-3400",
    name: "PAN-OS: Arbitrary File Creation Leads to OS Command Injection Vulnerability in GlobalProtect",
    description: "A command injection as a result of arbitrary file creation vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.\n\nCloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.",
    cwe: "CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')"
  },
  {
    cveID: "CVE-2024-3387",
    name: "PAN-OS: Weak Certificate Strength in Panorama Software Leads to Sensitive Information Disclosure",
    description: "A weak (low bit strength) device certificate in Palo Alto Networks Panorama software enables an attacker to perform a meddler-in-the-middle (MitM) attack to capture encrypted traffic between the Panorama management server and the firewalls it manages. With sufficient computing resources, the attacker could break encrypted communication and expose sensitive information that is shared between the management server and the firewalls.",
    cwe: "CWE-326 Inadequate Encryption Strength"
  },
  {
    cveID: "CVE-2024-3386",
    name: "PAN-OS: Predefined Decryption Exclusions Does Not Work as Intended",
    description: "An incorrect string comparison vulnerability in Palo Alto Networks PAN-OS software prevents Predefined Decryption Exclusions from functioning as intended. This can cause traffic destined for domains that are not specified in Predefined Decryption Exclusions to be unintentionally excluded from decryption.",
    cwe: "CWE-436 Interpretation Conflict"
  },
  {
    cveID: "CVE-2024-3385",
    name: "PAN-OS: Firewall Denial of Service (DoS) when GTP Security is Disabled",
    description: "A packet processing mechanism in Palo Alto Networks PAN-OS software enables a remote attacker to reboot hardware-based firewalls. Repeated attacks eventually cause the firewall to enter maintenance mode, which requires manual intervention to bring the firewall back online.\n\nThis affects the following hardware firewall models:\n- PA-5400 Series firewalls\n- PA-7000 Series firewalls",
    cwe: "CWE-20 Improper Input Validation"
  },
  {
    cveID: "CVE-2024-3384",
    name: "PAN-OS: Firewall Denial of Service (DoS) via Malformed NTLM Packets",
    description: "A vulnerability in Palo Alto Networks PAN-OS software enables a remote attacker to reboot PAN-OS firewalls when receiving Windows New Technology LAN Manager (NTLM) packets from Windows servers. Repeated attacks eventually cause the firewall to enter maintenance mode, which requires manual intervention to bring the firewall back online.",
    cwe: "CWE-1286 Improper Validation of Syntactic Correctness of Input"
  },
  {
    cveID: "CVE-2024-3388",
    name: "PAN-OS: User Impersonation in GlobalProtect SSL VPN",
    description: "A vulnerability in the GlobalProtect Gateway in Palo Alto Networks PAN-OS software enables an authenticated attacker to impersonate another user and send network packets to internal assets. However, this vulnerability does not allow the attacker to receive response packets from those internal assets.",
    cwe: "CWE-269 Improper Privilege Management"
  },
  {
    cveID: "CVE-2024-3383",
    name: "PAN-OS: Improper Group Membership Change Vulnerability in Cloud Identity Engine (CIE)",
    description: "A vulnerability in how Palo Alto Networks PAN-OS software processes data received from Cloud Identity Engine (CIE) agents enables modification of User-ID groups. This impacts user access to network resources where users may be inappropriately denied or allowed access to resources based on your existing Security Policy rules.",
    cwe: "CWE-282: Improper Ownership Management"
  },
  {
    cveID: "CVE-2024-3382",
    name: "PAN-OS: Firewall Denial of Service (DoS) via a Burst of Crafted Packets",
    description: "A memory leak exists in Palo Alto Networks PAN-OS software that enables an attacker to send a burst of crafted packets through the firewall that eventually prevents the firewall from processing traffic. This issue applies only to PA-5400 Series devices that are running PAN-OS software with the SSL Forward Proxy feature enabled.",
    cwe: "CWE-770 Allocation of Resources Without Limits or Throttling"
  },
  {
    cveID: "CVE-2024-8689",
    name: "ActiveMQ Content Pack: Cleartext Exposure of Credentials",
    description: "A problem with the ActiveMQ integration for both Cortex XSOAR and Cortex XSIAM can result in the cleartext exposure of the configured ActiveMQ credentials in log bundles.",
    cwe: "CWE-312 Cleartext Storage of Sensitive Information"
  },
  {
    cveID: "CVE-2024-8688",
    name: "PAN-OS: Arbitrary File Read Vulnerability in the Command Line Interface (CLI)",
    description: "An improper neutralization of matching symbols vulnerability in the Palo Alto Networks PAN-OS command line interface (CLI) enables authenticated administrators (including read-only administrators) with access to the CLI to to read arbitrary files on the firewall.",
    cwe: "CWE-155 Improper Neutralization of Wildcards or Matching Symbols"
  },
  {
    cveID: "CVE-2024-8687",
    name: "PAN-OS: Cleartext Exposure of GlobalProtect Portal Passcodes",
    description: "An information exposure vulnerability exists in Palo Alto Networks PAN-OS software that enables a GlobalProtect end user to learn both the configured GlobalProtect uninstall password and the configured disable or disconnect passcode. After the password or passcode is known, end users can uninstall, disable, or disconnect GlobalProtect even if the GlobalProtect app configuration would not normally permit them to do so.",
    cwe: "CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere"
  },
  {
    cveID: "CVE-2024-8691",
    name: "PAN-OS: User Impersonation in GlobalProtect Portal",
    description: "A vulnerability in the GlobalProtect portal in Palo Alto Networks PAN-OS software enables a malicious authenticated GlobalProtect user to impersonate another GlobalProtect user. Active GlobalProtect users impersonated by an attacker who is exploiting this vulnerability are disconnected from GlobalProtect. Upon exploitation, PAN-OS logs indicate that the impersonated user authenticated to GlobalProtect, which hides the identity of the attacker.",
    cwe: "CWE-863 Incorrect Authorization"
  },
  {
    cveID: "CVE-2024-8690",
    name: "Cortex XDR Agent: Local Windows Administrator Can Disable the Agent",
    description: "A problem with a detection mechanism in the Palo Alto Networks Cortex XDR agent on Windows devices enables a user with Windows administrator privileges to disable the agent. This issue may be leveraged by malware to disable the Cortex XDR agent and then to perform malicious activity.",
    cwe: "CWE-440: Expected Behavior Violation"
  },
  {
    cveID: "CVE-2024-8686",
    name: "PAN-OS: Command Injection Vulnerability",
    description: "A command injection vulnerability in Palo Alto Networks PAN-OS software enables an authenticated administrator to bypass system restrictions and run arbitrary commands as root on the firewall.",
    cwe: "CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
  },
  {
    cveID: "CVE-2024-9466",
    name: "Expedition: Cleartext Storage of Information Leads to Firewall Admin Credential Disclosure",
    description: "A cleartext storage of sensitive information vulnerability in Palo Alto Networks Expedition allows an authenticated attacker to reveal firewall usernames, passwords, and API keys generated using those credentials.",
    cwe: "CWE-532 Insertion of Sensitive Information into Log File"
  },
  {
    cveID: "CVE-2024-9470",
    name: "Cortex XSOAR: Information Disclosure Vulnerability",
    description: "A vulnerability in Cortex XSOAR allows the disclosure of incident data to users who do not have the privilege to view the data.",
    cwe: "CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere"
  },
  {
    cveID: "CVE-2024-9471",
    name: "PAN-OS: Privilege Escalation (PE) Vulnerability in XML API",
    description: "A privilege escalation (PE) vulnerability in the XML API of Palo Alto Networks PAN-OS software enables an authenticated PAN-OS administrator with restricted privileges to use a compromised XML API key to perform actions as a higher privileged PAN-OS administrator. For example, an administrator with \"Virtual system administrator (read-only)\" access could use an XML API key of a \"Virtual system administrator\" to perform write operations on the virtual system configuration even though they should be limited to read-only operations.",
    cwe: "CWE-269 Improper Privilege Management"
  },
  {
    cveID: "CVE-2024-9467",
    name: "Expedition: Reflected Cross-Site Scripting Vulnerability Leads to Expedition Session Disclosure",
    description: "A reflected XSS vulnerability in Palo Alto Networks Expedition enables execution of malicious JavaScript in the context of an authenticated Expedition user's browser if that user clicks on a malicious link, allowing phishing attacks that could lead to Expedition browser session theft.",
    cwe: "CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
  },
  {
    cveID: "CVE-2024-9474",
    name: "PAN-OS: Privilege Escalation (PE) Vulnerability in the Web Management Interface",
    description: "A privilege escalation vulnerability in Palo Alto Networks PAN-OS software allows a PAN-OS administrator with access to the management web interface to perform actions on the firewall with root privileges.\n\nCloud NGFW and Prisma Access are not impacted by this vulnerability.",
    cwe: "CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
  },
  {
    cveID: "CVE-2024-9463",
    name: "Expedition: Unauthenticated OS Command Injection Vulnerability Leads to Firewall Credential Disclosure",
    description: "An OS command injection vulnerability in Palo Alto Networks Expedition allows an unauthenticated attacker to run arbitrary OS commands as root in Expedition, resulting in disclosure of usernames, cleartext passwords, device configurations, and device API keys of PAN-OS firewalls.",
    cwe: "CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
  },
  {
    cveID: "CVE-2024-9472",
    name: "PAN-OS: Firewall Denial of Service (DoS) Using Specially Crafted Traffic",
    description: "A null pointer dereference in Palo Alto Networks PAN-OS software on PA-800 Series, PA-3200 Series, PA-5200 Series, and PA-7000 Series hardware platforms when Decryption policy is enabled allows an unauthenticated attacker to crash PAN-OS by sending specific traffic through the data plane, resulting in a denial of service (DoS) condition. Repeated attempts to trigger this condition will result in PAN-OS entering maintenance mode.",
    cwe: "CWE-476 NULL Pointer Dereference"
  },
  {
    cveID: "CVE-2024-9464",
    name: "Expedition: Authenticated OS Command Injection Vulnerability Leads to Firewall Admin Credential Disclosure",
    description: "An OS command injection vulnerability in Palo Alto Networks Expedition allows an authenticated attacker to run arbitrary OS commands as root in Expedition, resulting in disclosure of usernames, cleartext passwords, device configurations, and device API keys of PAN-OS firewalls.",
    cwe: "CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
  },
  {
    cveID: "CVE-2024-9468",
    name: "PAN-OS: Firewall Denial of Service (DoS) via a Maliciously Crafted Packet",
    description: "A memory corruption vulnerability in Palo Alto Networks PAN-OS software allows an unauthenticated attacker to crash PAN-OS due to a crafted packet through the data plane, resulting in a denial of service (DoS) condition. Repeated attempts to trigger this condition will result in PAN-OS entering maintenance mode.",
    cwe: "CWE-787 Out-of-bounds Write"
  },
  {
    cveID: "CVE-2024-9469",
    name: "Cortex XDR Agent: Local Windows User Can Disable the Agent",
    description: "A problem with a detection mechanism in the Palo Alto Networks Cortex XDR agent on Windows devices enables a user with Windows non-administrative privileges to disable the agent. This issue may be leveraged by malware to disable the Cortex XDR agent and then to perform malicious activity.",
    cwe: "CWE-754: Improper Check for Unusual or Exceptional Conditions"
  },
  {
    cveID: "CVE-2024-9465",
    name: "Expedition: SQL Injection Leads to Firewall Admin Credential Disclosure",
    description: "An SQL injection vulnerability in Palo Alto Networks Expedition allows an unauthenticated attacker to reveal Expedition database contents, such as password hashes, usernames, device configurations, and device API keys. With this, attackers can also create and read arbitrary files on the Expedition system.",
    cwe: "CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
  },
  {
    cveID: "CVE-2024-9473",
    name: "GlobalProtect App: Local Privilege Escalation (PE) Vulnerability",
    description: "A privilege escalation vulnerability in the Palo Alto Networks GlobalProtect app on Windows allows a locally authenticated non-administrative Windows user to escalate their privileges to NT AUTHORITY/SYSTEM through the use of the repair functionality offered by the .msi file used to install GlobalProtect.",
    cwe: "CWE-250 Execution with Unnecessary Privileges"
  },
  {
    cveID: "CVE-2024-0010",
    name: "PAN-OS: Reflected Cross-Site Scripting (XSS) Vulnerability in GlobalProtect Portal",
    description: "A reflected cross-site scripting (XSS) vulnerability in the GlobalProtect portal feature of Palo Alto Networks PAN-OS software enables execution of malicious JavaScript (in the context of a user's browser) if a user clicks on a malicious link, allowing phishing attacks that could lead to credential theft.",
    cwe: "CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
  },
  {
    cveID: "CVE-2024-0007",
    name: "PAN-OS: Stored Cross-Site Scripting (XSS) Vulnerability in the Panorama Web Interface",
    description: "A cross-site scripting (XSS) vulnerability in Palo Alto Networks PAN-OS software enables a malicious authenticated read-write administrator to store a JavaScript payload using the web interface on Panorama appliances. This enables the impersonation of another authenticated administrator.",
    cwe: "CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
  },
  {
    cveID: "CVE-2024-0011",
    name: "PAN-OS: Reflected Cross-Site Scripting (XSS) Vulnerability in Captive Portal Authentication",
    description: "A reflected cross-site scripting (XSS) vulnerability in the Captive Portal feature of Palo Alto Networks PAN-OS software enables execution of malicious JavaScript (in the context of an authenticated Captive Portal user's browser) if a user clicks on a malicious link, allowing phishing attacks that could lead to credential theft.",
    cwe: "CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
  },
  {
    cveID: "CVE-2024-0008",
    name: "PAN-OS: Insufficient Session Expiration Vulnerability in the Web Interface",
    description: "Web sessions in the management interface in Palo Alto Networks PAN-OS software do not expire in certain situations, making it susceptible to unauthorized access.",
    cwe: "CWE-613 Insufficient Session Expiration"
  },
  {
    cveID: "CVE-2024-0012",
    name: "PAN-OS: Authentication Bypass in the Management Web Interface (PAN-SA-2024-0015)",
    description: "An authentication bypass in Palo Alto Networks PAN-OS software enables an unauthenticated attacker with network access to the management web interface to gain PAN-OS administrator privileges to perform administrative actions, tamper with the configuration, or exploit other authenticated privilege escalation vulnerabilities.",
    cwe: "CWE-306 Missing Authentication for Critical Function"
  },
  {
    cveID: "CVE-2024-0009",
    name: "PAN-OS: Improper IP Address Verification in GlobalProtect Gateway",
    description: "An improper verification vulnerability in the GlobalProtect gateway feature of Palo Alto Networks PAN-OS software enables a malicious user with stolen credentials to establish a VPN connection from an unauthorized IP address.",
    cwe: "CWE-940 Improper Verification of Source of a Communication Channel"
  },
  {
    cveID: "CVE-2024-5916",
    name: "PAN-OS: Cleartext Exposure of External System Secrets",
    description: "An information exposure vulnerability in Palo Alto Networks PAN-OS software enables a local system administrator to unintentionally disclose secrets, passwords, and tokens of external systems. A read-only administrator who has access to the config log, can read secrets, passwords, and tokens to external systems.",
    cwe: "CWE-313: Cleartext Storage in a File or on Disk"
  },
  {
    cveID: "CVE-2024-5920",
    name: "PAN-OS: Stored Cross-Site Scripting (XSS) Vulnerability in PAN-OS Enables Impersonation of a Legitimate Administrator",
    description: "A cross-site scripting (XSS) vulnerability in Palo Alto Networks PAN-OS software enables an authenticated read-write Panorama administrator to push a specially crafted configuration to a PAN-OS node. This enables impersonation of a legitimate PAN-OS administrator who can perform restricted actions on the PAN-OS node after the execution of JavaScript in the legitimate PAN-OS administrator's browser.",
    cwe: "CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
  },
  {
    cveID: "CVE-2024-5921",
    name: "GlobalProtect App: Insufficient Certificate Validation Leads to Privilege Escalation",
    description: "An insufficient certification validation issue in the Palo Alto Networks GlobalProtect app enables attackers to connect the GlobalProtect app to arbitrary servers. This can enable a local non-administrative operating system user or an attacker on the same subnet to install malicious root certificates on the endpoint and subsequently install malicious software signed by the malicious root certificates on that endpoint.",
    cwe: "CWE-295 Improper Certificate Validation"
  },
  {
    cveID: "CVE-2024-5917",
    name: "PAN-OS: Server-Side Request Forgery in WildFire",
    description: "A server-side request forgery in PAN-OS software enables an unauthenticated attacker to use the administrative web interface as a proxy, which enables the attacker to view internal network resources not otherwise accessible.",
    cwe: "CWE-918 Server-Side Request Forgery (SSRF)"
  },
  {
    cveID: "CVE-2024-5910",
    name: "Expedition: Missing Authentication Leads to Admin Account Takeover",
    description: "Missing authentication for a critical function in Palo Alto Networks Expedition can lead to an Expedition admin account takeover for attackers with network access to Expedition.",
    cwe: "CWE-306 Missing Authentication for Critical Function"
  },
  {
    cveID: "CVE-2024-5906",
    name: "Prisma Cloud Compute: Stored Cross-Site Scripting (XSS) Vulnerability in the Web Interface",
    description: "A cross-site scripting (XSS) vulnerability in Palo Alto Networks Prisma Cloud Compute software enables a malicious administrator with add/edit permissions for identity providers to store a JavaScript payload using the web interface on Prisma Cloud Compute. This enables a malicious administrator to perform actions in the context of another user's browser when accessed by that other user.",
    cwe: "CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
  },
  {
    cveID: "CVE-2024-5907",
    name: "Cortex XDR Agent: Local Privilege Escalation (PE) Vulnerability",
    description: "A privilege escalation (PE) vulnerability in the Palo Alto Networks Cortex XDR agent on Windows devices enables a local user to execute programs with elevated privileges. However, execution does require the local user to successfully exploit a race condition, which makes this vulnerability difficult to exploit.",
    cwe: "CWE-269 Improper Privilege Management"
  },
  {
    cveID: "CVE-2024-5911",
    name: "PAN-OS: File Upload Vulnerability in the Panorama Web Interface",
    description: "An arbitrary file upload vulnerability in Palo Alto Networks Panorama software enables an authenticated read-write administrator with access to the web interface to disrupt system processes and crash the Panorama. Repeated attacks eventually cause the Panorama to enter maintenance mode, which requires manual intervention to bring the Panorama back online.",
    cwe: "CWE-434 Unrestricted Upload of File with Dangerous Type"
  },
  {
    cveID: "CVE-2024-5908",
    name: "GlobalProtect App: Encrypted Credential Exposure via Log Files",
    description: "A problem with the Palo Alto Networks GlobalProtect app can result in exposure of encrypted user credentials, used for connecting to GlobalProtect, in application logs. Normally, these application logs are only viewable by local users and are included when generating logs for troubleshooting purposes. This means that these encrypted credentials are exposed to recipients of the application logs.",
    cwe: "CWE-532: Insertion of Sensitive Information into Log File"
  },
  {
    cveID: "CVE-2024-5912",
    name: "Cortex XDR Agent: Improper File Signature Verification Checks",
    description: "An improper file signature check in Palo Alto Networks Cortex XDR agent may allow an attacker to bypass the Cortex XDR agent's executable blocking capabilities and run untrusted executables on the device. This issue can be leveraged to execute untrusted software without being detected or blocked.",
    cwe: "CWE-347 Improper Verification of Cryptographic Signature"
  },
  {
    cveID: "CVE-2024-5913",
    name: "PAN-OS: Improper Input Validation Vulnerability in PAN-OS",
    description: "An improper input validation vulnerability in Palo Alto Networks PAN-OS software enables an attacker with the ability to tamper with the physical file system to elevate privileges.",
    cwe: "CWE-20 Improper Input Validation"
  },
  {
    cveID: "CVE-2024-5905",
    name: "Cortex XDR Agent: Local Windows User Can Disrupt Functionality of the Agent",
    description: "A problem with a protection mechanism in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local low privileged Windows user to disrupt some functionality of the agent. However, they are not able to disrupt Cortex XDR agent protection mechanisms using this vulnerability.",
    cwe: "CWE-346 Origin Validation Error"
  },
  {
    cveID: "CVE-2024-5909",
    name: "Cortex XDR Agent: Local Windows User Can Disable the Agent",
    description: "A problem with a protection mechanism in the Palo Alto Networks Cortex XDR agent on Windows devices allows a low privileged local Windows user to disable the agent. This issue may be leveraged by malware to disable the Cortex XDR agent and then to perform malicious activity.",
    cwe: "CWE-269 Improper Privilege Management"
  },
  {
    cveID: "CVE-2024-5914",
    name: "Cortex XSOAR: Command Injection in CommonScripts Pack",
    description: "A command injection issue in Palo Alto Networks Cortex XSOAR CommonScripts Pack allows an unauthenticated attacker to execute arbitrary commands within the context of an integration container.",
    cwe: "CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')"
  },
  {
    cveID: "CVE-2024-5918",
    name: "PAN-OS: Improper Certificate Validation Enables Impersonation of a Legitimate GlobalProtect User",
    description: "An improper certificate validation vulnerability in Palo Alto Networks PAN-OS software enables an authorized user with a specially crafted client certificate to connect to an impacted GlobalProtect portal or GlobalProtect gateway as a different legitimate user. This attack is possible only if you \"Allow Authentication with User Credentials OR Client Certificate.\"",
    cwe: "CWE-295 Improper Certificate Validation"
  },
  {
    cveID: "CVE-2024-5919",
    name: "PAN-OS: Authenticated XML External Entities (XXE) Injection Vulnerability",
    description: "A blind XML External Entities (XXE) injection vulnerability in the Palo Alto Networks PAN-OS software enables an authenticated attacker to exfiltrate arbitrary files from firewalls to an attacker controlled server. This attack requires network access to the firewall management interface.",
    cwe: "CWE-611 Improper Restriction of XML External Entity Reference"
  },
  {
    cveID: "CVE-2024-5915",
    name: "GlobalProtect App: Local Privilege Escalation (PE) Vulnerability",
    description: "A privilege escalation (PE) vulnerability in the Palo Alto Networks GlobalProtect app on Windows devices enables a local user to execute programs with elevated privileges.",
    cwe: "CWE-732 Incorrect Permission Assignment for Critical Resource"
  }
];