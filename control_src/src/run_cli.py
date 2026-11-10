import subprocess

class CommandRunner:
    def __init__(self, command):
        self.command = command

    def run(self):
        try:
            # Use Popen to execute commands, stdout and stderr pipes are used to get command output
            process = subprocess.Popen(self.command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()  # Wait for command execution to complete and get output
            returncode = process.returncode  # Get the return code of the command

            # return error or output
            return stdout, stderr, returncode

        except Exception as e:
            return str(e)






if __name__ == "__main__":
    command = "/path/control_commands/src/control_commands.py"
    runner = CommandRunner(command)
    output, error, code = runner.run()

    print("Output:", output)
    print("Error:", error)
    print("Return Code:", code)