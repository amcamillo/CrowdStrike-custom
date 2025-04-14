# Sample Log Kit Shipper - SLK Shipper
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A simple Python Flask web application designed to generate and send simulated security log events based on MITRE ATT&CK® techniques to an HTTP Event Collector (HEC) endpoint, primarily intended for testing SIEM platforms like CrowdStrike Falcon LogScale / Next-Gen SIEM.

## Overview

SLK Shipper helps security analysts, SIEM engineers, and developers test detection rules, dashboards, parsers, and data ingestion pipelines by providing realistic, albeit simulated, log data. Instead of relying on simple, repetitive test logs, this tool generates event chains mimicking adversary behaviors observed in the wild.

**Key Goals:**

*   **Realistic Data:** Generate logs reflecting common adversary TTPs and sequences (completely machine generated, though).
*   **Schema Alignment:** Structure logs based on the CrowdStrike Common Schema (CPS) principles to facilitate parsing and analysis within Falcon LogScale/NG-SIEM.
*   **Diverse Scenarios:** Simulate various attack chains inspired by known adversary groups (e.g., FIN7, APT29, Wizard Spider) and generic attack flows.
*   **Multiple Categories:** Generate logs across different categories including `process`, `network`, `email`, `authentication`, `registry`, `file`, and `cloud`.
*   **Ease of Use:** Provide a simple web interface for configuration and triggering log generation.

## Features

*   **Web-Based UI:** Simple interface built with Flask to configure HEC endpoint and select scenarios.
*   **Pre-defined Attack Chains:** Choose from multiple attack chains emulating different adversary objectives and techniques.
*   **ATT&CK TTP Simulation:** Generates events corresponding to specific MITRE ATT&CK techniques (Txxxx).
*   **HEC Log Shipping:** Sends generated data via standard HTTP Event Collector protocol (compatible with Splunk HEC and Falcon LogScale HEC).
*   **Configurable Endpoint:** Specify your target HEC URL and authentication token directly in the UI.
*   **Structured Logging:** Events are generated as JSON objects aiming for compatibility with CrowdStrike's schema.

## How it Works

SLK Shipper operates as a local web server. The user interacts with the web UI to provide their HEC endpoint details and select an attack chain. The Flask backend then:

1.  Receives the user's request.
2.  Calls the appropriate Python function to generate a list of simulated log event dictionaries for the selected chain.
3.  Iterates through the generated events.
4.  Formats each event into the appropriate HEC JSON payload structure (adapting for LogScale's `/humio-structured` vs. standard `/collector/event` endpoints).
5.  Sends each event payload via an HTTP POST request to the user-specified HEC URL with the provided token.
6.  Returns the status of the sending process to the web UI.

### Diagram
![image](https://github.com/user-attachments/assets/b33b68e0-c7db-418f-b173-802fa2564db8)


## Setup and Installation
### Prerequisites:
Python 3.7+
Clone the Repository:
git clone https://github.com/your-username/slk-shipper.git # Replace with your repo URL
cd slk-shipper
Bash

Create a Virtual Environment (Recommended):
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows (cmd)
python -m venv venv
.\venv\Scripts\activate

# Windows (PowerShell - may require execution policy change)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install Dependencies:
Create a requirements.txt file with the following content:
Flask>=2.0
requests>=2.25

Then run:
pip install -r requirements.txt

(Note: If you want to try getting the real LSASS PID on Windows, uncomment psutil in requirements.txt and install it. The app will fall back to random PIDs if psutil is not installed or fails.)

# Usage
Run the Flask Application:

python app.py

(Look for output indicating the server is running, typically on http://127.0.0.1:5001 or http://0.0.0.0:5001)
Access the Web UI: Open your web browser and navigate to http://127.0.0.1:5001 (or the address shown in the terminal).

Configure HEC:

Enter the full HEC URL for your SIEM instance.
For Falcon LogScale, prefer the /api/v1/humio-structured endpoint.
The standard /services/collector/event endpoint is also supported.
Enter your HEC Token.

Select Scenario: Choose an attack chain simulation from the dropdown list.
Send Logs: Click the "Send Event Chain" button.
Monitor: Observe the status messages displayed in the web UI. Check your SIEM platform to verify log ingestion and parsing.


Important Notes
Parsing: While the generated logs are structured JSON and aim to align with the CrowdStrike Common Schema, you will likely need a custom parser in Falcon LogScale associated with the cs:test:attacksim:chain sourcetype for optimal field extraction and mapping within the platform. A sample parser is not included here but can be built based on the structure observed in the sent_payloads_sample output in the UI.
Simulation: This tool generates simulated data. It does not execute real malicious code. Field values (PIDs, timestamps, hashes, IPs) are often randomized or based on plausible examples, not exact replicas of real-world events.
SSL Verification: For ease of use in test environments, SSL certificate verification for the HEC endpoint is disabled by default in the requests.post call (verify=False). Do not use this configuration in production environments. Ensure valid certificates and enable verification (verify=True) if connecting to production systems.
HEC Endpoint Type: The application attempts to detect LogScale's /api/v1/humio-structured endpoint vs. a standard /services/collector/event endpoint to format the payload correctly. Ensure you provide the correct URL type.
Customization


You can add new simulations by:
Creating new generate_t... functions in app.py for individual TTPs, ensuring they return a dictionary matching the expected structure.
Creating new generate_chain_... functions that call the TTP helpers in sequence and return a list of event dictionaries.
Adding the new chain function key and its generator function to the SCENARIOS dictionary in app.py.
(Optional) Update the display name logic in the index route if needed.

