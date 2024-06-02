# SOC Automation Projects

In today’s ever-evolving cybersecurity landscape, the need for robust Security Operations Centers (SOCs) is more critical than ever. With cyber threats becoming increasingly sophisticated, organizations must continuously adapt and enhance their detection and response capabilities to safeguard their assets and data.

One effective approach is to build a fully automated SOC home lab, empowering cybersecurity enthusiasts and professionals alike to hone their skills in a controlled environment. This guide explores the process of setting up such a lab using open-source tools and cloud services.

## Table of Contents
- [Architecture Diagram](#architecture-diagram)
- [Step 1: Initial Setup](#step-1-initial-setup)
- [Step 2: Setting Up the Environment](#step-2-setting-up-the-environment)
- [Step 3: Configuration](#step-3-configuration)
- [Step 4: Deploying a New Agent](#step-4-deploying-a-new-agent)
- [Step 5: Generating and Ingesting Telemetry Data](#step-5-generating-and-ingesting-telemetry-data)
- [Step 6: Integrating with Shuffle (SOAR)](#step-6-integrating-with-shuffle-soar)
- [Additional Resources](#additional-resources)


## Architecture Diagram

![SOC Architecture Diagram](images/architecture_diagram.png)

## Step 1: Initial Setup

### Components
1. **Windows 10 Client with Wazuh Agent**: Sends telemetry data to the Wazuh Manager.
2. **Wazuh Manager**: Evaluates telemetry data and triggers alerts.
3. **Shuffle**: Handles alerts and creates notifications in The Hive.
4. **The Hive**: Acts as a case management system.
5. **SOC Analyst**: Investigates the alerts.

### Workflow
1. **Windows 10 Client**: Sends telemetry data via Wazuh Agent to Wazuh Manager.
2. **Wazuh Manager**: Evaluates telemetry data and triggers alerts if rules are matched.
3. **Shuffle**: Creates alerts in The Hive and sends email notifications to SOC Analysts.
4. **SOC Analyst**: Performs investigation based on the alerts.

## Step 2: Setting Up the Environment

### Requirements
- **Windows 10 with Sysmon Installed**
- **VPS on Digital Ocean**: Hosts Wazuh Server and The Hive Server.

### Tools Description
1. **Sysmon**: A Windows system service and device driver that logs system activity to the Windows event log.
2. **Wazuh**: An open-source cybersecurity platform that integrates SIEM and XDR capabilities, providing security analytics, intrusion detection, and incident response.
   - **Components**: Indexer, Server, Dashboard.
3. **The Hive**: An open-source security incident response platform used as a case management system.

### VM Setup
- **Windows 10**: Install Sysmon.
- **Ubuntu (for Wazuh and The Hive)**: Spin up VMs in the cloud.

### Installation Guides
- [VM Installation Guide](https://example.com/vm-installation-guide)
- [Sysmon Installation Guide](https://example.com/sysmon-installation-guide)

### Creating Droplets on Digital Ocean
1. Create droplets for Wazuh and The Hive.
2. Set up the firewall rules to allow necessary traffic.

### Wazuh and The Hive Setup
1. **Upgrade and Update**: Ensure your system is up to date via CLI.
2. **Wazuh Installation**: Follow the provided instructions.
3. **Save Credentials**: Record the username and password for the web interface.

### The Hive Setup
- Prepare space for The Hive.

## Step 3: Configuration

### Cassandra Database Configuration
1. Edit the Cassandra configuration file:
   ```bash
   sudo nano /etc/cassandra/cassandra.yaml
   
2. Update the following parameters:
   ```bash
   cluster_name: xyz
   listen_address: <public IP of The Hive>
   rpc_address: <public IP of The Hive>
   seed_address: <public IP of The Hive>:7000

3. Save the file and run the following commands:
   ```bash
   sudo systemctl stop cassandra.service
   sudo rm -rf /var/lib/cassandra/*
   sudo systemctl start cassandra.service
   sudo systemctl status cassandra.service

### Elasticsearch Configuration
1. Edit the Elasticsearch configuration file:
   ```bash
    Copy code
    sudo nano /etc/elasticsearch/elasticsearch.yml

2. Update the following parameters:
    ```elasticsearch.yaml
    cluster.name: thehive
    node.name: node-1
    network.host: <public IP of The Hive>
    http.port: 9200
    
3. Save the file and run the following commands:
   ```bash
    sudo systemctl start elasticsearch
    sudo systemctl enable elasticsearch
    sudo systemctl status elasticsearch

Check Service Status:
- Verify the status of Cassandra, Elasticsearch, and The Hive services.

### The Hive Web Interface
1. Access The Hive at `http://<thehive_public_ip>:9000`.
2. Default login credentials:
    -Username: `admin@thehive.local`
    -Password: `secret`
   
### Extract and Save Passwords:
1. Extract passwords:
  ```bash
  ls
  tar -xvf wazuh-install-files.tar
  ls
  cat wazuh-passwords.txt1
```
2. Save the Wazuh API user and password.

#step-4-deploying-a-new-agent

### Deploying a New Agent
  1. Deploy Agent from Wazuh Interface: Fill in the details and copy the Wazuh agent installer.
  2. Windows Powershell: Run the installer with admin privileges.
  3. Verify: Check the Wazuh web interface for the new agent and its active status.

#step-5-generating-and-ingesting-telemetry-data

### Generating and Ingesting Telemetry Data
  1. Manipulate ossec.conf File on Windows
  2. Go to your Windows machine and search for ossec-agent in Program Files.
  3. Open the ossec.conf file using admin privileges.
     
### Download Mimikatz
   1. Download Mimikatz on your Windows machine using CLI with admin privileges.

### Configure ossec.conf on Wazuh Manager
  1. Go to the Wazuh terminal and edit the `ossec.conf` file.



### Restart Wazuh Manager
  1. Restart the Wazuh Manager:
      ```bash
     sudo systemctl restart wazuh-manager.service
     
  2.  Navigate to the logs:
      ```bash
    cd /var/ossec/logs/archives
    ls
    
### Update Wazuh Filebeat Configuration
  1.  Make changes in the Wazuh Filebeat configuration.
  2.  Restart Filebeat:
      ```bash
      sudo systemctl restart filebeat

### Create Index and Custom Rules in Wazuh Dashboard
  1. Go to the Wazuh dashboard and create an index.
  2. Create custom rules by editing the `local_rules.xml` file.
```     
<!-- Local rules -->

<!-- Modify it at your will. -->
<!-- Copyright (C) 2015, Wazuh Inc. -->

<!-- Example -->
<group name="local,syslog,sshd,">
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
  <rule id="100002" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Mimikatz Usage Detected</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>
</group>
```

### Rerun Mimikatz and Check Detection
  1. Change the executable file name of Mimikatz and rerun the Mimikatz command in the CLI.
  2. Check the Wazuh interface for detection of Mimikatz.

#step-6-integrating-with-shuffle-soar

### Integrating with Shuffle (SOAR)
-Connect Wazuh to Shuffle
  1. Use the integration tag in the ossec.conf file to connect Wazuh to Shuffle.

###  Workflow for Mimikatz Alert Handling
  1. Mimikatz Alert: Sent to Shuffle.
  2. Shuffle: Receives the alert, extracts the SHA 256 hash, and checks the reputation score with VirusTotal.
  3.  Create Alert in The Hive: Send the details to The Hive to create an alert.
  4.  Email Notification: Send an email to the SOC Analyst to begin the investigation.

### Additional Assistance
  - Use ChatGPT to write regex for SHA 256.
  - Use VirusTotal API to check the hash and return the value.


#additional-resources

### Additional Resources
  -  Wazuh Documentation
  -  The Hive Project
  -  Sysmon Documentation
  -  VirusTotal API Documentation












