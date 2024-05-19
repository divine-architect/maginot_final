import subprocess
import flask
from flask import Flask, send_from_directory
import nmap
from crontab import CronTab

def install_simplemonitor(config_1,website_url):
    """Installs SimpleMonitor using pip."""
    try:
        subprocess.run(["pip", "install", "simplemonitor"])
        
        if config_1 == 'http_monitoring':
            with open('monitor.ini','w') as f:
                f.write(f"""[monitor]
interval = 60 
tolerance = 3 
[reporting]
loggers=logfile                 
[logfile]
type=logfile
filename=monitor.log
""")
            with open('monitors.ini','w') as f:
                f.write(f"""[monitor1]
type = http
url = {website_url} 
match = (?i)200 OK
timeout = 10
""")
        elif config_1 == 'average_load':
            with open('monitor.ini','w') as f:
                f.write(f"""[monitor]
interval = 60
tolerance = 3
[reporting]
loggers=logfile
[logfile]
type=logfile
filename=monitor.log
""")
            with open('monitors.ini','w') as f:
                f.write(f"""

[monitor1]
type = loadavg
limit = 5


[monitor2]
type = loadavg
limit = 3
average = 1

[monitor3]
type = loadavg
limit = 4
average = 5

[monitor4]
type = loadavg
limit = 4.5
average = 15
""")
        print("SimpleMonitor installed successfully!")
        subprocess.run(["simplemonitor"])
    except subprocess.CalledProcessError as e:
        print(f"Error installing SimpleMonitor: {e}")


def vul_tracker(user_ip):
    # Create an instance of the PortScanner class
    nm = nmap.PortScanner()
    # Perform a script scan to detect vulnerabilities
    print('g')
    nm.scan(hosts=user_ip, arguments='-sV --script=vuln')
    print('l')
    # Get the list of hosts that were scanned
    hosts = nm.all_hosts()
    print(hosts)
    # Iterate over the hosts and print the vulnerabilities found
    for host in hosts:
        print(f"Host: {host}")
        print("Vulnerabilities:")
        # Get the script output for the "vuln" script
        vuln_script_output = nm[host].get('script', {}).get('vuln', {})
        with open('vulnerabilities.log', 'w') as f:
            for vuln in vuln_script_output:
                vuln_details = vuln_script_output[vuln]
                f.write(vuln_details)

def create_app():
    app = Flask(__name__)

    @app.route('/monitor.log')
    def serve_log_file():
        try:
            return send_from_directory('.', 'monitor.log')
        except FileNotFoundError:
            return flask.abort(404)

    @app.route('/vuln.log')
    def serve_vuktn_log_file():
        try:
            return send_from_directory('.', 'vulnerabilities.log')
        except FileNotFoundError:
            return flask.abort(404)

    return app

def setup_cron():
    # Create a new cron tab instance
    cron = CronTab(user=True)

    # Create a new cron job to execute the script every time the system starts up
    job = cron.new(command=f'python {__file__}', comment='Run script on startup')
    job.every_reboot()

    # Create a new cron job to run simplemonitor at startup
    simplemonitor_job = cron.new(command='simplemonitor', comment='Run simplemonitor on startup')
    simplemonitor_job.every_reboot()

    # Write the cron jobs to the cron tab
    cron.write()

if __name__ == '__main__':
    install_simplemonitor('http_monitoring', 'https://google.com')
    vul_tracker()
    app = create_app()
    app.run(debug=True)
    setup_cron()
