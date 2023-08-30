"""
Author: Jack He (jackhe@microsoft.com)

This utility script is useful for creating a toc.yml file specifically for use with DocFx.

DocFx is a dotnet tool for generating documentation from markdown files.
It requires a toc.yml file to link markdowns to generate the static site.
"""

import os
import yaml

def create_yaml_entry(file_path):
    file_name = os.path.basename(file_path)
    name = os.path.splitext(file_name)[0]
    entry = {'name': name, 'href': file_name}
    return entry

def create_yaml_from_directory(directory_path, output_file):
    yaml_data = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            if not file.endswith('.md'):
                continue  # Skips non markdown files.
            file_path = os.path.join(root, file)
            entry = create_yaml_entry(file_path)
            yaml_data.append(entry)
        break

    with open(output_file, 'w') as f:
        yaml.dump(yaml_data, f, default_flow_style=False)

if __name__ == "__main__":
    input_directory = input("Enter the directory path: ")
    output_file = input_directory + "/toc.yml"

    create_yaml_from_directory(input_directory, output_file)
    print("YAML file created successfully.")