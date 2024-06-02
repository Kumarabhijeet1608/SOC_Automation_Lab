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

![SOC Architecture Diagram](https://github.com/Kumarabhijeet1608/SOC_Automation_Lab/blob/main/Image%20File/Architecture_Dig.png)

## Step 1: Initial Setup

### Components
1. **Windows 10 Client with Wazuh Agent**: Sends telemetry data to the Wazuh Manager.
2. **Wazuh Manager**: [Wazuh](https://wazuh.com/) is an open source security monitoring solution which collects and analyzes host security data. It is a fork of the older, better known OSSEC project. Evaluate telemetry data and triggers alerts.
3. **Shuffle**: [Shuffle](https://shuffler.io/) is an Open Source SOAR solution for making orchestration easy between security tools. Handles alerts and creates notifications in The Hive.
4. **The Hive**: [TheHive](https://thehive-project.org/) is a scalable 3-in-1 open source and free Security Incident Response Platform designed to make life easier for SOCs, CSIRTs, CERTs, and any information security practitioner dealing with security incidents that need to be investigated and acted upon swiftly.Acts as a case management system. - The official GitRepo of TheHive is [HERE](https://github.com/TheHive-Project/TheHive)
5. **SOC Analyst**: Investigates the alerts.

### Workflow
1. **Windows 10 Client**: Sends telemetry data via Wazuh Agent to Wazuh Manager.
2. **Wazuh Manager**: Evaluates telemetry data and triggers alerts if rules are matched.
3. **Shuffle**: Creates alerts in The Hive and sends email notifications to SOC Analysts.
4. **SOC Analyst**: Performs investigation based on the alerts.

## Step 2: Setting Up the Environment

### Requirements
- **Windows 10 with Sysmon Installed in it**
- **VPS on Digital Ocean**: Hosts Wazuh Server and The Hive Server.
- **Ubuntu (for Wazuh and The Hive)**: Spin up VMs in the cloud VPS [DigitalOcean](https://cloud.digitalocean.com/).
- Use the [LINK](https://m.do.co/c/e2ce5a05f701) <- To get a free $200 credit for the first 60 days with Digital Ocean


### Tools Description
1. **Sysmon**: A Windows system service and device driver that logs system activity to the Windows event log.
2. **Wazuh**: An open-source cybersecurity platform that integrates SIEM and XDR capabilities, providing security analytics, intrusion detection, and incident response.
   - **Components**: Indexer, Server, Dashboard.
3. **The Hive**: An open-source security incident response platform used as a case management system.

### Installation Guides
- [VM Installation Guide](https://www.youtube.com/watch?v=nvdnQX9UkMY)
- [Sysmon Installation Guide](https://www.youtube.com/watch?v=uJ7pv6blyog)

### Creating Droplets on Digital Ocean
1. Create droplets for Wazuh and The Hive.
   ![droplets for Wazuh and The Hive](https://github.com/Kumarabhijeet1608/SOC_Automation_Lab/blob/main/Image%20File/8.png)
2. Set up the firewall rules to allow necessary traffic.



### Wazuh Setup
   ![Wazuh Setup](https://github.com/Kumarabhijeet1608/SOC_Automation_Lab/blob/main/Image%20File/5.png)
1. **Upgrade and Update**: Ensure your system is up to date via CLI.
    ```bash
       apt-get update && apt-get upgrade -y  
2. **Wazuh Specification**: Follow the provided instructions.
    ```bash
      RAM: 8GB+
      HDD: 50GB+
      OS: Ubuntu 22.04 LTS
3.    Install Wazuh 4.7
      ```bash
         curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
4.   Extract Wazuh Credentials
      ```bash
         sudo tar -xvf wazuh-install-files.tar
   
4. **Save Credentials**: Record the username and password for the web interface.
      ![web interface Credentials](https://github.com/Kumarabhijeet1608/SOC_Automation_Lab/blob/main/Image%20File/4.png)





### The Hive Setup
 ![The Hive Setup](https://github.com/Kumarabhijeet1608/SOC_Automation_Lab/blob/main/Image%20File/TheHive.png)
1. **Upgrade and Update**: Ensure your system is up to date via CLI.
    ```bash
       apt-get update && apt-get upgrade -y  
2. **The Hive Specifications**: Follow the provided instructions.
    ```bash
      RAM: 8GB+ (Recommend 16 GB)
      HDD: 50+ GB
      OS: Ubuntu 22.04 LTS
2. Dependences
   ```bash
      Installing TheHive 5
      apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release
3. Install Java
   ```bash
      wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
      echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
      sudo apt update
      sudo apt install java-common java-11-amazon-corretto-jdk
      echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
      export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
4. Install Cassandra
   ```bash
      wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
      echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
      sudo apt update
      sudo apt install cassandra
5. Install ElasticSearch
   ```bash
      wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
      sudo apt-get install apt-transport-https
      echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
      sudo apt update
      sudo apt install elasticsearch

6. Install The Hive
   ```bash
      wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
      echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
      sudo apt-get update
      sudo apt-get install -y thehive

 ### The Hive Web Interface
1. Access The Hive at `http://<thehive_public_ip>:9000`.
2. Default login credentials:
   ```
    -Username: admin@thehive.local
    -Password: secret
   ```




  
## Step 3: Configuration in The Hive

### Cassandra Database Configuration
1. Edit the Cassandra configuration file:
   ```bash
   sudo nano /etc/cassandra/cassandra.yaml
   
2. Update the following parameters in the yaml file:
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

 ![Cassandra](https://github.com/Kumarabhijeet1608/SOC_Automation_Lab/blob/main/Image%20File/10.png)


### Elasticsearch Configuration
1. Edit the Elasticsearch configuration file:
   ```bash
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

 ![Elasticsearch](https://github.com/Kumarabhijeet1608/SOC_Automation_Lab/blob/main/Image%20File/11.png)



### Check the Service Status:
- Verify the status of Cassandra, Elasticsearch, and The Hive services.

 ![Service Status](https://github.com/Kumarabhijeet1608/SOC_Automation_Lab/blob/main/Image%20File/14.png)




   
### Extract and Save Passwords from Wazuh:
1. Extract passwords:
  ```bash
  ls
  tar -xvf wazuh-install-files.tar
  ls
  cat wazuh-passwords.txt1
```
2. Save the Wazuh API user and password.



## Step 4: Deploying a New Agent

### Deploying a New Agent
  1. Deploy Agent from Wazuh Interface: Fill in the details and copy the Wazuh agent installer.
  2. Windows Powershell: Paste the Wazuh agent installer & Run the installer with admin privileges.
  3. Verify: Check the Wazuh web interface for the new agent and its active status.
     
 ![Active Status](https://github.com/Kumarabhijeet1608/SOC_Automation_Lab/blob/main/Image%20File/15.png)



## Step 5: Generating and Ingesting Telemetry Data

### Download Mimikatz
   1. Download Mimikatz on your Windows machine using CLI with admin privileges.
      - [Mimikatz](https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20220919)
      22nd img

        
### Generating and Ingesting Telemetry Data
  1. Manipulate `ossec.conf` File on Windows Machine.
  2. Search your Windows machine for `ossec-agent` in Program Files.
  3. Open the `ossec.conf` file using admin privileges.

 ![ossec.conf](https://github.com/Kumarabhijeet1608/SOC_Automation_Lab/blob/main/Image%20File/17.png)

  4. Go back to Wazuh Dashboard.
  5. Under Events
  6. There is an Alert Index
  7. Search for Sysmon Events

### Configure ossec.conf on Wazuh Manager
  1. Go to the Wazuh terminal and edit the `ossec.conf` file.

25th image .....

### Update Wazuh Filebeat Configuration

  1.  Make changes in the Wazuh Filebeat configuration.
    ```bash
      `nano /etc/filebeat/filebeat.yml`
  2. There you need to set `archives`: `enabled`: `true`     
      
  3.  Restart Filebeat:
      ```bash
         sudo systemctl restart filebeat
      ```
  4. Go back to Wazuh Dashboard and create an Index.

     
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
24th image

  6.   Go to wazuh-archives-**
  7.   Search mimikatz
  27th image 
  8.  If you don't find anything re-run the `mimikatz` in the windows machine via CLI.

  9. Herd back to wazuh & grep for mimikatz
     ```bash
        cat archives.json | grep -i mimikatz
     ```
     

### Rerun Mimikatz and Check Detection
  1. Change the executable file name of Mimikatz and rerun the Mimikatz command in the CLI.
  2. Check the Wazuh interface for the detection of Mimikatz.



## Step 6: Integrating with Shuffle (SOAR)

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

## additional-resources

### Additional Resources
  -  Wazuh Documentation
  -  The Hive Project
  -  Sysmon Documentation
  -  VirusTotal API Documentation












