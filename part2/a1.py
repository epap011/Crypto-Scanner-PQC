import os

output_file = "merged_prompt.txt"

def append_file_content(output_path, directory="files"):
    try:
        if not os.path.exists(directory):
            print(f"Directory '{directory}' does not exist.")
            return

        with open(output_path, 'w', encoding='utf-8') as output:
            for file_name in os.listdir(directory):
                file_path = os.path.join(directory, file_name)
                if os.path.isfile(file_path):
                    try:
                        with open(file_path, 'r', encoding='utf-8') as file:
                            content = file.read()

                        output.write(f"=== File: {file_name} ===\n")
                        output.write(content)
                        output.write("\n\n")
                    except Exception as e:
                        print(f"Could not read file {file_name}: {e}")
        print(f"All file contents have been merged into '{output_path}'")
    except Exception as e:
        print(f"An error occurred: {e}")

append_file_content(output_file, directory="files")
