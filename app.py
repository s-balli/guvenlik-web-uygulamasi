from flask import Flask, render_template, request
import subprocess
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    # Get the list of selected tests from the form
    selected_tests = request.form.getlist('tests')

    if not target:
        return render_template('index.html', error="Target cannot be empty.")

    # Sanitize the target to prevent command injection
    sanitized_target = ''.join(c for c in target if c.isalnum() or c in '.-')

    # Construct the command to run the script
    # The first argument is the script itself, followed by the target,
    # and then the list of selected tests.
    command = ["./security_test.sh", sanitized_target] + selected_tests

    try:
        # Run the script and capture the output
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=600,  # 10-minute timeout
            check=True, # Raise an exception if the script fails
            env=dict(os.environ, PATH=f"{os.environ['PATH']}:/opt/testssl.sh:/opt/sqlmap")
        )
        output = result.stdout
    except subprocess.TimeoutExpired:
        output = "Scan timed out after 10 minutes."
    except subprocess.CalledProcessError as e:
        output = f"An error occurred while running the scan:\n{e.stderr}"
    except FileNotFoundError:
        output = "Error: security_test.sh not found or not executable."

    return render_template('index.html', output=output, target=sanitized_target)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)