import os

output_file = "merged_prompt.txt"

def append_file_content(output_path):
    with open(output_path, 'w', encoding='utf-8') as output:
        for file_name in os.listdir('.'):
            if os.path.isfile(file_name):
                try:
                    with open(file_name, 'r', encoding='utf-8') as file:
                        content = file.read()
                
                    output.write(f"=== File: {file_name} ===\n")
                    output.write(content)
                    output.write("\n\n")
                except Exception as e:
                    print(f"Could not read file {file_name}: {e}")
    print(f"All file contents have been merged into '{output_path}'")

append_file_content(output_file)
