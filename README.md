# probe
A probe "Fuzzer" bash script that sends various API requests using cURL and jq that could trigger unique errors that might be missed in software engineering

Replication of Project

1. Install the required tools, including bash (default on Linux/macOS or via Git Bash on Windows), curl (included with Git Bash), and jq using sudo apt install jq on Linux, brew install jq on macOS, or winget install jqlang.jq on Windows.

2. Clone the repository and navigate into the /probe directory.

3. Open both api_probe.sh and run_baseline.sh and set your API endpoint by updating the API_URL variable.

4. Optionally configure authentication by entering your test email and password into the script variables.

5. Run the baseline test suite by executing ./run_baseline.sh, which stores its results in logs/baseline_run.json.

6. Run the LLM-style fuzzing probe using ./api_probe.sh, which saves its output in logs/probe_run.json.

