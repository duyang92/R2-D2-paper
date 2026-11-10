import generate
import Data
import run_cli
import time
import readline

if __name__ == "__main__":
    Tasks = generate.TaskSetter()

    flag_clear = raw_input("Clear the table in P4 (y/n): ")
    if flag_clear == "y":
        command = "./p4_clear.py"
        clear_runner = run_cli.CommandRunner(command)
        output, error, code = clear_runner.run()
        # print("Output:", output)
        # print("Error:", error)
        # print("Return Code:", code)
    
    flag = 0
    while True:
        generate.alloc_time = 0
        # Input the lists of tasks for adding and releasing 
        add_tasks = raw_input("Enter tasks to add (space-separated): ")
        release_tasks = raw_input("Enter tasks to release (space-separated): ")

        # Add Defense Tasks
        start_time = time.time()
        add_commands = Tasks.add_task(add_tasks)
        release_commands = Tasks.release_task(release_tasks)
        end_time = time.time()
        generate_time = end_time - start_time
        print("\nAllocating Sketch Time: {} seconds.\n".format(generate.alloc_time))
        print("Generating Defense_Task Time: {} seconds.\n".format(generate_time - generate.alloc_time))
        print(add_commands)
        # Release Defense Tasks
        print(release_commands)